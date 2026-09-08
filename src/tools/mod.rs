//! Tool reali per Fase 3: effetti collaterali veri + compensazioni vere.
//!
//! - [`FsWriteTool`]: scrive un file su disco, in `compensate` lo elimina.
//! - [`MockPaymentTool`]: pagamento simulato con ledger, in `compensate` storna.
//! - [`CrashTool`]: crash deterministico per demo/test di rollback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::error::KernelError;
use crate::security::SecurityGuard;
use crate::types::{ToolContext, ToolOutput};

/// Scrive un file su disco.
///
/// Args: `{ "path": "<percorso>", "content": "<testo>" }`.
/// Compensazione: elimina il file (idempotente).
///
/// Se costruito con [`FsWriteTool::with_guard`], ogni `execute`/`compensate`
/// valida il path con `check_path_access` (difesa in profondità: blocca
/// traversal e file sensibili anche se chiamato fuori dal kernel).
pub struct FsWriteTool {
    guard: Option<std::sync::Arc<dyn SecurityGuard>>,
}

impl FsWriteTool {
    /// Tool senza sandbox locale (la protezione resta a carico del kernel).
    pub fn new() -> Self {
        Self { guard: None }
    }

    /// Tool con sandbox locale integrata.
    pub fn with_guard(guard: std::sync::Arc<dyn SecurityGuard>) -> Self {
        Self { guard: Some(guard) }
    }

    /// Risolve il path: con guard → path assoluto validato; senza → raw.
    fn resolve_path(&self, raw: &str) -> Result<String, KernelError> {
        match &self.guard {
            Some(g) => Ok(g
                .check_path_access(std::path::Path::new(raw))?
                .to_string_lossy()
                .to_string()),
            None => Ok(raw.to_owned()),
        }
    }

    fn path_from_args(args: &Value) -> Result<String, KernelError> {
        // Args: path obbligatorio, content opzionale.
        args.get("path")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| KernelError::ToolExecution {
                tool_id: "fs.write".to_owned(),
                message: "missing required arg 'path' (string)".to_owned(),
            })
    }
}

impl Default for FsWriteTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::traits::TransactionalTool for FsWriteTool {
    fn id(&self) -> &'static str {
        "fs.write"
    }

    async fn execute(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput, KernelError> {
        let raw = Self::path_from_args(&args)?;
        let path = self.resolve_path(&raw)?;
        let content = args.get("content").and_then(Value::as_str).unwrap_or("");
        // Crea le directory parent mancanti (write ricorsiva, come ci si
        // aspetta da un tool di scrittura file).
        if let Some(parent) = std::path::Path::new(&path).parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| KernelError::ToolExecution {
                    tool_id: self.id().to_owned(),
                    message: format!(
                        "mkdir '{}' failed (seq {}): {e}",
                        parent.display(),
                        ctx.step_seq
                    ),
                })?;
        }
        tokio::fs::write(&path, content)
            .await
            .map_err(|e| KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: format!("write '{path}' failed (seq {}): {e}", ctx.step_seq),
            })?;
        tracing::info!(tool = "fs.write", path = %path, seq = ctx.step_seq, "file written");
        Ok(
            ToolOutput::new(json!({ "path": path, "bytes": content.len() }))
                .with_effect(format!("wrote file {path}")),
        )
    }

    async fn compensate(
        &self,
        ctx: &ToolContext,
        args: Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        let raw = Self::path_from_args(&args).map_err(|_| KernelError::CompensationFailed {
            tool_id: self.id().to_owned(),
            message: "missing arg 'path' for compensation".to_owned(),
        })?;
        let path = self
            .resolve_path(&raw)
            .map_err(|e| KernelError::CompensationFailed {
                tool_id: self.id().to_owned(),
                message: format!("security blocked compensation: {e}"),
            })?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                tracing::info!(tool = "fs.write", path = %path, seq = ctx.step_seq, "file deleted (compensated)");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Idempotente: già eliminato → successo.
                tracing::info!(tool = "fs.write", path = %path, "already gone (idempotent compensate)");
                Ok(())
            }
            Err(e) => Err(KernelError::CompensationFailed {
                tool_id: self.id().to_owned(),
                message: format!("delete '{path}' failed: {e}"),
            }),
        }
    }
}

/// Pagamento simulato con ledger condiviso.
///
/// Args: `{ "payment_id": "<id>"?, "amount": <n>? }` (id autogenerato se assente).
/// Stati ledger: `"CHARGED"` → `"REFUNDED"` (compensazione, idempotente).
#[derive(Debug, Clone)]
pub struct MockPaymentTool {
    ledger: Arc<Mutex<HashMap<String, String>>>,
}

impl MockPaymentTool {
    /// Nuovo tool con ledger vuoto.
    pub fn new() -> Self {
        Self {
            ledger: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Stato di un pagamento (`None` se sconosciuto).
    pub fn status(&self, payment_id: &str) -> Option<String> {
        self.ledger
            .lock()
            .map(|g| g.get(payment_id).cloned())
            .unwrap_or(None)
    }

    /// Numero di voci nel ledger (per verificare l'anti-retry nei test).
    pub fn ledger_size(&self) -> usize {
        self.ledger.lock().map(|g| g.len()).unwrap_or(0)
    }
    fn set(&self, payment_id: &str, status: &str) {
        if let Ok(mut g) = self.ledger.lock() {
            g.insert(payment_id.to_owned(), status.to_owned());
        } else if let Err(poisoned) = self.ledger.lock() {
            // Non dovrebbe accadere nei test; fallback best-effort senza panic.
            let _ = poisoned
                .into_inner()
                .insert(payment_id.to_owned(), status.to_owned());
        }
    }
}

impl Default for MockPaymentTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::traits::TransactionalTool for MockPaymentTool {
    fn id(&self) -> &'static str {
        "mock.pay"
    }

    async fn execute(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput, KernelError> {
        let payment_id = args
            .get("payment_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("pay-{}-{}", ctx.session_id, ctx.step_seq));
        let amount = args.get("amount").cloned().unwrap_or(json!(100));

        // Idempotenza: retry con stesso id già CHARGED/REFUNDED → ritorna Ok.
        if let Some(existing) = self.status(&payment_id) {
            tracing::info!(tool = "mock.pay", payment_id = %payment_id, status = %existing, "idempotent replay");
            return Ok(
                ToolOutput::new(json!({ "payment_id": payment_id, "amount": amount }))
                    .with_effect(format!("payment {payment_id} already {existing}")),
            );
        }

        self.set(&payment_id, "CHARGED");
        tracing::info!(tool = "mock.pay", payment_id = %payment_id, seq = ctx.step_seq, "payment CHARGED");
        Ok(
            ToolOutput::new(json!({ "payment_id": payment_id, "amount": amount }))
                .with_effect(format!("charged {payment_id}")),
        )
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        args: Value,
        output: ToolOutput,
    ) -> Result<(), KernelError> {
        let payment_id = args
            .get("payment_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                output
                    .data
                    .get("payment_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or_else(|| KernelError::CompensationFailed {
                tool_id: self.id().to_owned(),
                message: "missing 'payment_id' in args/output".to_owned(),
            })?;

        // Idempotente: REFUNDED resta REFUNDED.
        self.set(&payment_id, "REFUNDED");
        tracing::info!(tool = "mock.pay", payment_id = %payment_id, "payment REFUNDED");
        Ok(())
    }
}

/// Tool che va in crash deterministico (per demo/test di rollback).
pub struct CrashTool;

#[async_trait::async_trait]
impl crate::traits::TransactionalTool for CrashTool {
    fn id(&self) -> &'static str {
        "crash.tool"
    }

    async fn execute(&self, ctx: &ToolContext, _args: Value) -> Result<ToolOutput, KernelError> {
        tracing::error!(
            tool = "crash.tool",
            seq = ctx.step_seq,
            "intentional crash!"
        );
        Err(KernelError::ToolExecution {
            tool_id: self.id().to_owned(),
            message: format!("intentional crash at seq {}", ctx.step_seq),
        })
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        // Mai committato → mai compensato; no-op per sicurezza.
        Ok(())
    }
}
