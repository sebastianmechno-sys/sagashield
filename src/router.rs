//! L0 Inference Router — scelta deterministica del backend per task.
//!
//! Il kernel è model-agnostic: il router non esegue inferenza, produce un
//! **piano** auditabile `{ backend, vram, costo, latenza, energia }`.
//! Regole:
//! - **VRAM-fit**: stima `params * byte/quant + overhead KV-cache`. Se non
//!   sta nei GB disponibili, il backend locale è escluso (niente OOM).
//! - **Context-fit**: `context_tokens <= context_max`.
//! - **SLO**: `max_cost_per_1k`, `max_latency_ms`, `max_watt_per_task`
//!   filtrano i candidati. Se nessuno passa, errore `NoFeasibleBackend`
//!   (il chiamante scala con burst cloud o rifiuta, mai degrado silenzioso).
//! - **Preferenza locale**: a parità di fattibilità vince il locale
//!   (sovranità, $0 marginale, niente egress).
//!
//! Le stime sono euristiche documentate, non benchmark: servono per
//! instradare e contabilizzare, non per promettere throughput.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{KernelError, KernelResult};
use crate::traits::TransactionalTool;
use crate::types::{ToolContext, ToolOutput};

/// Quantizzazione supportata con byte/parametro effettivi (stima GGUF-like).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Quant {
    F16,
    Q8,
    Q6,
    #[default]
    Q4,
    Iq3,
    Q2,
}

impl Quant {
    /// Byte effettivi per parametro (pesi).
    pub fn bytes_per_param(self) -> f64 {
        match self {
            Self::F16 => 2.0,
            Self::Q8 => 1.0,
            Self::Q6 => 0.75,
            Self::Q4 => 0.55,
            Self::Iq3 => 0.42,
            Self::Q2 => 0.33,
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "f16" | "fp16" | "bf16" => Self::F16,
            "q8" | "q8_0" => Self::Q8,
            "q6" | "q6_k" => Self::Q6,
            "iq3" | "q3" | "iq3_xs" | "ad-iq3" => Self::Iq3,
            "q2" | "iq2" => Self::Q2,
            _ => Self::Q4,
        }
    }
}

/// Backend locale (GPU singola, first-class 16GB).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalBackend {
    pub model_id: String,
    pub params_b: f64,
    pub quant: Quant,
    /// VRAM totale disponibile sulla macchina (GB).
    pub vram_gb: f64,
    pub context_max: u64,
    /// Throughput tipico (tok/s) per stima latenza.
    pub tok_per_s: f64,
    /// Watt medi durante decode (per ledger energia).
    pub watts: f64,
    /// Qualità 0-100 (benchmark interno, per tie-break).
    pub quality: i64,
}

/// Backend cloud (burst, a consumo).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudBackend {
    pub model_id: String,
    pub cost_per_1k_tokens: f64,
    /// Latenza p50 stimata per task tipico (ms).
    pub latency_ms: u64,
    /// Wh stimati per 1k token (per ledger CO2).
    pub wh_per_1k: f64,
    pub context_max: u64,
    pub quality: i64,
}

/// Catalogo backends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BackendCatalog {
    pub local: Vec<LocalBackend>,
    pub cloud: Vec<CloudBackend>,
}

impl BackendCatalog {
    /// Preset realistici 2026 per singola GPU consumer.
    pub fn consumer_presets(vram_gb: f64) -> Self {
        Self {
            local: vec![
                LocalBackend {
                    model_id: "qwen3.5-9b-q6".to_owned(),
                    params_b: 9.0,
                    quant: Quant::Q6,
                    vram_gb,
                    context_max: 32_768,
                    tok_per_s: 55.0,
                    watts: 220.0,
                    quality: 68,
                },
                LocalBackend {
                    model_id: "qwen3.8-27b-iq3".to_owned(),
                    params_b: 27.0,
                    quant: Quant::Iq3,
                    vram_gb,
                    context_max: 8_192,
                    tok_per_s: 28.0,
                    watts: 300.0,
                    quality: 78,
                },
                LocalBackend {
                    model_id: "gpt-oss-20b-mxfp4".to_owned(),
                    params_b: 20.0,
                    quant: Quant::Q4,
                    vram_gb,
                    context_max: 16_384,
                    tok_per_s: 34.0,
                    watts: 280.0,
                    quality: 75,
                },
            ],
            cloud: vec![
                CloudBackend {
                    model_id: "cloud/haiku-class".to_owned(),
                    cost_per_1k_tokens: 0.0008,
                    latency_ms: 900,
                    wh_per_1k: 0.4,
                    context_max: 200_000,
                    quality: 80,
                },
                CloudBackend {
                    model_id: "cloud/sonnet-class".to_owned(),
                    cost_per_1k_tokens: 0.006,
                    latency_ms: 1_800,
                    wh_per_1k: 1.1,
                    context_max: 200_000,
                    quality: 90,
                },
            ],
        }
    }
}

/// Requisiti del task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    /// Token di contesto necessari (prompt + KV budget).
    pub context_tokens: u64,
    /// Token attesi in output (per stima costo/latenza/energia).
    pub expected_output_tokens: u64,
    /// Qualità minima accettabile (0-100).
    pub min_quality: i64,
}

/// SLO del chiamante. `None` = nessun vincolo su quella dimensione.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SloPolicy {
    pub max_cost_per_1k: Option<f64>,
    pub max_latency_ms: Option<u64>,
    pub max_wh_per_task: Option<f64>,
    /// Se true (default), a parità di fattibilità vince il locale.
    pub prefer_local: Option<bool>,
}

/// Piano scelto, auditabile e loggabile nel WAL come output tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutePlan {
    pub backend: String,
    pub is_local: bool,
    pub est_vram_gb: f64,
    pub est_cost_usd: f64,
    pub est_latency_ms: u64,
    pub est_wh: f64,
    pub reason: String,
}

/// Stima VRAM: pesi + overhead KV-cache lineare nel contesto.
///
/// `kv_gb = context_tokens * params_b * 1.2e-7` — euristica conservativa
/// tarata su 9-35B a 8-32k (sovrastima leggera > sottostima che causa OOM).
pub fn estimate_vram_gb(params_b: f64, quant: Quant, context_tokens: u64) -> f64 {
    let weights = params_b * quant.bytes_per_param();
    let kv = context_tokens as f64 * params_b * 1.2e-7;
    weights + kv + 0.6 // runtime + overhead fisso
}

/// Router puro (nessun I/O): catalogo + policy -> piano.
pub struct InferenceRouter {
    pub catalog: BackendCatalog,
}

impl InferenceRouter {
    pub fn new(catalog: BackendCatalog) -> Self {
        Self { catalog }
    }

    pub fn plan(&self, task: &TaskSpec, slo: &SloPolicy) -> KernelResult<RoutePlan> {
        let prefer_local = slo.prefer_local.unwrap_or(true);
        let mut local_feasible: Vec<RoutePlan> = Vec::new();

        for b in &self.catalog.local {
            if task.context_tokens > b.context_max || b.quality < task.min_quality {
                continue;
            }
            let vram = estimate_vram_gb(b.params_b, b.quant, task.context_tokens);
            if vram > b.vram_gb {
                continue;
            }
            let secs = task.expected_output_tokens as f64 / b.tok_per_s.max(1.0);
            let latency_ms = (secs * 1000.0) as u64;
            let wh = b.watts * secs / 3600.0;
            if let Some(max_ms) = slo.max_latency_ms
                && latency_ms > max_ms
            {
                continue;
            }
            if let Some(max_wh) = slo.max_wh_per_task
                && wh > max_wh
            {
                continue;
            }
            // Locale: costo marginale ~0 (hardware già pagato).
            if let Some(max_c) = slo.max_cost_per_1k
                && 0.0 > max_c
            {
                continue;
            }
            local_feasible.push(RoutePlan {
                backend: b.model_id.clone(),
                is_local: true,
                est_vram_gb: (vram * 100.0).round() / 100.0,
                est_cost_usd: 0.0,
                est_latency_ms: latency_ms,
                est_wh: (wh * 1000.0).round() / 1000.0,
                reason: format!(
                    "local fit: {:.1}GB <= {:.0}GB VRAM, ctx {} <= {}",
                    vram, b.vram_gb, task.context_tokens, b.context_max
                ),
            });
        }

        if prefer_local && !local_feasible.is_empty() {
            // Migliore qualità, poi minore energia.
            local_feasible.sort_by(|a, b| {
                b.est_wh
                    .partial_cmp(&a.est_wh)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            // Riordina per qualità del backend originale: lookup semplice.
            local_feasible.sort_by_key(|p| {
                std::cmp::Reverse(
                    self.catalog
                        .local
                        .iter()
                        .find(|b| b.model_id == p.backend)
                        .map(|b| b.quality)
                        .unwrap_or(0),
                )
            });
            if let Some(best) = local_feasible.into_iter().next() {
                info!(backend = %best.backend, "router: local plan");
                return Ok(best);
            }
        }

        let mut cloud_feasible: Vec<RoutePlan> = Vec::new();
        let total_k = (task.context_tokens + task.expected_output_tokens) as f64 / 1000.0;
        for b in &self.catalog.cloud {
            if task.context_tokens > b.context_max || b.quality < task.min_quality {
                continue;
            }
            let cost = total_k * b.cost_per_1k_tokens;
            let wh = total_k * b.wh_per_1k;
            if let Some(max_c) = slo.max_cost_per_1k
                && cost > max_c * total_k
            {
                continue;
            }
            if let Some(max_ms) = slo.max_latency_ms
                && b.latency_ms > max_ms
            {
                continue;
            }
            if let Some(max_wh) = slo.max_wh_per_task
                && wh > max_wh
            {
                continue;
            }
            cloud_feasible.push(RoutePlan {
                backend: b.model_id.clone(),
                is_local: false,
                est_vram_gb: 0.0,
                est_cost_usd: (cost * 1_000_000.0).round() / 1_000_000.0,
                est_latency_ms: b.latency_ms,
                est_wh: (wh * 1000.0).round() / 1000.0,
                reason: format!(
                    "cloud burst: ctx {} <= {}",
                    task.context_tokens, b.context_max
                ),
            });
        }
        // Più economico prima, poi minore energia.
        cloud_feasible.sort_by(|a, b| {
            a.est_cost_usd
                .partial_cmp(&b.est_cost_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    a.est_wh
                        .partial_cmp(&b.est_wh)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        if let Some(best) = cloud_feasible.into_iter().next() {
            info!(backend = %best.backend, "router: cloud plan");
            return Ok(best);
        }

        // Se prefer_local=false e il cloud fallisce, riprova il locale come fallback.
        if !prefer_local && !self.catalog.local.is_empty() {
            let mut retry: Vec<RoutePlan> = Vec::new();
            for b in &self.catalog.local {
                if task.context_tokens > b.context_max || b.quality < task.min_quality {
                    continue;
                }
                let vram = estimate_vram_gb(b.params_b, b.quant, task.context_tokens);
                if vram > b.vram_gb {
                    continue;
                }
                let secs = task.expected_output_tokens as f64 / b.tok_per_s.max(1.0);
                retry.push(RoutePlan {
                    backend: b.model_id.clone(),
                    is_local: true,
                    est_vram_gb: (vram * 100.0).round() / 100.0,
                    est_cost_usd: 0.0,
                    est_latency_ms: (secs * 1000.0) as u64,
                    est_wh: (b.watts * secs / 3600.0 * 1000.0).round() / 1000.0,
                    reason: "local fallback after cloud miss".to_owned(),
                });
            }
            if let Some(best) = retry.into_iter().next() {
                return Ok(best);
            }
        }

        Err(KernelError::ToolExecution {
            tool_id: "router.plan".to_owned(),
            message: format!(
                "NO_FEASIBLE_BACKEND ctx={} out={} min_q={} (vram/cost/latency/energy SLO)",
                task.context_tokens, task.expected_output_tokens, task.min_quality
            ),
        })
    }
}

/// Tool `router.plan` — read-only, per `AgentKernel`.
///
/// Args: `{ context_tokens, expected_output_tokens, min_quality?,
///          vram_gb?, prefer_local?, max_cost_per_1k?, max_latency_ms?, max_wh_per_task? }`.
/// `vram_gb` costruisce il preset consumer al volo; in produzione il
/// catalogo va iniettato via `RouterPlanTool::with_catalog`.
pub struct RouterPlanTool {
    catalog: Arc<std::sync::Mutex<BackendCatalog>>,
}

impl RouterPlanTool {
    pub fn with_catalog(catalog: BackendCatalog) -> Self {
        Self {
            catalog: Arc::new(std::sync::Mutex::new(catalog)),
        }
    }

    pub fn consumer(vram_gb: f64) -> Self {
        Self::with_catalog(BackendCatalog::consumer_presets(vram_gb))
    }
}

#[async_trait::async_trait]
impl TransactionalTool for RouterPlanTool {
    fn id(&self) -> &'static str {
        "router.plan"
    }

    async fn execute(
        &self,
        _ctx: &ToolContext,
        args: serde_json::Value,
    ) -> Result<ToolOutput, KernelError> {
        let context_tokens = args
            .get("context_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: "missing required field 'context_tokens' (u64)".to_owned(),
            })?;
        let expected_output_tokens = args
            .get("expected_output_tokens")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(512);
        let task = TaskSpec {
            context_tokens,
            expected_output_tokens,
            min_quality: args
                .get("min_quality")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
        };
        let slo = SloPolicy {
            max_cost_per_1k: args
                .get("max_cost_per_1k")
                .and_then(serde_json::Value::as_f64),
            max_latency_ms: args
                .get("max_latency_ms")
                .and_then(serde_json::Value::as_u64),
            max_wh_per_task: args
                .get("max_wh_per_task")
                .and_then(serde_json::Value::as_f64),
            prefer_local: Some(
                args.get("prefer_local")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
            ),
        };
        // Catalogo dinamico se il chiamante passa vram_gb esplicita.
        if let Some(vram) = args.get("vram_gb").and_then(serde_json::Value::as_f64) {
            let router = InferenceRouter::new(BackendCatalog::consumer_presets(vram));
            let plan = router.plan(&task, &slo)?;
            return Ok(ToolOutput::new(serde_json::to_value(&plan).map_err(|e| {
                KernelError::ToolExecution {
                    tool_id: self.id().to_owned(),
                    message: format!("plan serialization failed: {e}"),
                }
            })?)
            .with_effect(format!("routed to {}", plan.backend)));
        }
        let catalog = self
            .catalog
            .lock()
            .map_err(|e| KernelError::Lock(e.to_string()))?
            .clone();
        let plan = InferenceRouter::new(catalog).plan(&task, &slo)?;
        Ok(ToolOutput::new(serde_json::to_value(&plan).map_err(|e| {
            KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: format!("plan serialization failed: {e}"),
            }
        })?)
        .with_effect(format!("routed to {}", plan.backend)))
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: serde_json::Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::Quant;
    use super::estimate_vram_gb;

    #[test]
    fn vram_estimate_orders_quant_correctly() {
        let ctx = 8_192;
        let f16 = estimate_vram_gb(9.0, Quant::F16, ctx);
        let q4 = estimate_vram_gb(9.0, Quant::Q4, ctx);
        assert!(f16 > q4);
        assert!(q4 < 16.0);
    }
}
