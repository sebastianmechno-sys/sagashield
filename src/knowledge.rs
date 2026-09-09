//! L1 Knowledge Fabric — RAG governata per agenti affidabili.
//!
//! Risolve il failure mode dominante dei pilot enterprise (MIT NANDA 95%):
//! risposte plausibili ma non grounding su contesto stale/frammentato.
//!
//! Garanzie:
//! - **Lineage**: ogni record ha `source/owner/version/license`.
//! - **Freshness**: `ttl_secs` opzionale + flag `quarantined`. Lo stale non
//!   raggiunge mai l'LLM se `require_fresh = true` (default).
//! - **Citazioni**: ogni hit produce `Citation { record_id, excerpt }`
//!   verificabile in 1 click.
//! - **No-answer-from-memory**: [`KnowledgeFabric::require_grounded`]
//!   ritorna [`KernelError::InsufficientGrounding`] invece di inventare.
//!
//! Design volutamente senza embedding esterni: scoring lessicale
//! deterministico (token-overlap) per build offline, test stabili e audit.
//! Un backend vettoriale può sostituire `score()` senza cambiare il contratto.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{KernelError, KernelResult};
use crate::traits::TransactionalTool;
use crate::types::{ToolContext, ToolOutput};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS knowledge_records (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    owner           TEXT NOT NULL,
    version         TEXT NOT NULL,
    content         TEXT NOT NULL,
    license         TEXT NOT NULL DEFAULT 'internal',
    ttl_secs        INTEGER,
    quarantined     INTEGER NOT NULL DEFAULT 0,
    updated_at_secs INTEGER NOT NULL,
    created_at_secs INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_source ON knowledge_records(source);
CREATE INDEX IF NOT EXISTS idx_knowledge_quarantine ON knowledge_records(quarantined);
"#;

/// Secondi Unix correnti (per TTL). Fallisce solo se l'orologio è prima del 1970.
pub fn now_secs() -> KernelResult<i64> {
    let dur =
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| KernelError::ToolExecution {
                tool_id: "knowledge.clock".to_owned(),
                message: format!("system clock before epoch: {e}"),
            })?;
    Ok(dur.as_secs() as i64)
}

/// Input per l'ingest di un documento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRecordInput {
    /// Dove vive la verità (es. `crm://policies/refund`, `s3://docs/v3`).
    pub source: String,
    /// Team proprietario (es. `support-ops`).
    pub owner: String,
    /// Versione del documento (es. `v3.2.1`, git sha).
    pub version: String,
    /// Testo governato da cui l'agente può citare.
    pub content: String,
    /// Licenza/provenance (es. `internal`, `cc-by-4.0`). Default `internal`.
    #[serde(default = "default_license")]
    pub license: String,
    /// TTL in secondi. `None` = non scade mai.
    pub ttl_secs: Option<i64>,
}

fn default_license() -> String {
    "internal".to_owned()
}

/// Record persistito con lineage completa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeRecord {
    pub id: String,
    pub source: String,
    pub owner: String,
    pub version: String,
    pub content: String,
    pub license: String,
    pub ttl_secs: Option<i64>,
    pub quarantined: bool,
    pub updated_at_secs: i64,
    pub created_at_secs: i64,
}

impl KnowledgeRecord {
    /// `true` se il TTL è superato a `now_secs` oppure è quarantenato.
    pub fn is_stale_at(&self, now: i64) -> bool {
        if self.quarantined {
            return true;
        }
        match self.ttl_secs {
            Some(ttl) => now.saturating_sub(self.updated_at_secs) > ttl,
            None => false,
        }
    }
}

/// Citazione verificabile (1-click verify).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub record_id: String,
    pub source: String,
    pub version: String,
    pub excerpt: String,
}

/// Hit con score e flag stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundedHit {
    pub record_id: String,
    pub source: String,
    pub version: String,
    pub excerpt: String,
    pub score: i64,
    pub stale: bool,
}

/// Policy di retrieval (difensiva di default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalPolicy {
    /// Max hit ritornati (default 3).
    pub max_hits: usize,
    /// Se `true` (default), i record stale/quarantenati sono esclusi.
    pub require_fresh: bool,
    /// Se `Some`, solo queste licenze passano (provenance gate).
    pub allowed_licenses: Option<Vec<String>>,
    /// Overlap minimo di token per considerare un hit (default 1).
    pub min_overlap: usize,
}

impl Default for RetrievalPolicy {
    fn default() -> Self {
        Self {
            max_hits: 3,
            require_fresh: true,
            allowed_licenses: None,
            min_overlap: 1,
        }
    }
}

/// Fabric thread-safe (`Mutex<Connection>`), condivisibile via `Arc`.
pub struct KnowledgeFabric {
    conn: Mutex<Connection>,
}

impl KnowledgeFabric {
    /// Apre (o crea) il fabric su file.
    pub fn open(path: impl AsRef<Path>) -> KernelResult<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let fabric = Self {
            conn: Mutex::new(conn),
        };
        fabric.init_schema()?;
        Ok(fabric)
    }

    /// Fabric in-memory (ideale per test ed esempi).
    pub fn open_in_memory() -> KernelResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let fabric = Self {
            conn: Mutex::new(conn),
        };
        fabric.init_schema()?;
        Ok(fabric)
    }

    fn init_schema(&self) -> KernelResult<()> {
        let conn = self.lock()?;
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    fn lock(&self) -> KernelResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| KernelError::Lock(e.to_string()))
    }

    /// Ingest con timestamp corrente. Ritorna l'ID (UUID v4).
    pub fn ingest(&self, input: NewRecordInput) -> KernelResult<String> {
        let now = now_secs()?;
        self.ingest_at(input, now, now)
    }

    /// Ingest con timestamp esplicito (deterministico, per test TTL).
    pub fn ingest_at(
        &self,
        input: NewRecordInput,
        created_at_secs: i64,
        updated_at_secs: i64,
    ) -> KernelResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO knowledge_records
             (id, source, owner, version, content, license, ttl_secs, quarantined, updated_at_secs, created_at_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
            params![
                id,
                input.source,
                input.owner,
                input.version,
                input.content,
                input.license,
                input.ttl_secs,
                updated_at_secs,
                created_at_secs,
            ],
        )?;
        info!(record_id = %id, source = %input.source, "knowledge ingest");
        Ok(id)
    }

    /// Lookup per ID.
    pub fn get(&self, id: &str) -> KernelResult<Option<KnowledgeRecord>> {
        let conn = self.lock()?;
        let row: Option<KnowledgeRecord> = conn
            .query_row(
                "SELECT id, source, owner, version, content, license, ttl_secs, quarantined, updated_at_secs, created_at_secs
                 FROM knowledge_records WHERE id = ?1",
                params![id],
                |r| {
                    Ok(KnowledgeRecord {
                        id: r.get(0)?,
                        source: r.get(1)?,
                        owner: r.get(2)?,
                        version: r.get(3)?,
                        content: r.get(4)?,
                        license: r.get(5)?,
                        ttl_secs: r.get(6)?,
                        quarantined: r.get::<_, i64>(7)? != 0,
                        updated_at_secs: r.get(8)?,
                        created_at_secs: r.get(9)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Marca come quarantenati tutti i record con TTL superato. Ritorna il conteggio.
    pub fn quarantine_expired(&self, now: i64) -> KernelResult<u64> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "UPDATE knowledge_records SET quarantined = 1
             WHERE quarantined = 0 AND ttl_secs IS NOT NULL
               AND (?1 - updated_at_secs) > ttl_secs",
            params![now],
        )?;
        if changed > 0 {
            warn!(quarantined = changed, "knowledge TTL expired");
        }
        Ok(changed as u64)
    }

    /// Retrieval lessicale deterministico con gate freshness + licenza.
    pub fn retrieve(
        &self,
        query: &str,
        policy: &RetrievalPolicy,
    ) -> KernelResult<Vec<GroundedHit>> {
        let now = now_secs()?;
        self.retrieve_at(query, policy, now)
    }

    /// Variante deterministica con `now` esplicito (per test).
    pub fn retrieve_at(
        &self,
        query: &str,
        policy: &RetrievalPolicy,
        now: i64,
    ) -> KernelResult<Vec<GroundedHit>> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }
        let max_hits = policy.max_hits.max(1);
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, source, owner, version, content, license, ttl_secs, quarantined, updated_at_secs, created_at_secs
             FROM knowledge_records",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(KnowledgeRecord {
                id: r.get(0)?,
                source: r.get(1)?,
                owner: r.get(2)?,
                version: r.get(3)?,
                content: r.get(4)?,
                license: r.get(5)?,
                ttl_secs: r.get(6)?,
                quarantined: r.get::<_, i64>(7)? != 0,
                updated_at_secs: r.get(8)?,
                created_at_secs: r.get(9)?,
            })
        })?;

        let mut scored: Vec<(KnowledgeRecord, i64)> = Vec::new();
        for record in rows {
            let record = record.map_err(KernelError::Sqlite)?;
            // License gate.
            if let Some(allowed) = &policy.allowed_licenses
                && !allowed.iter().any(|l| l == &record.license)
            {
                continue;
            }
            let stale = record.is_stale_at(now);
            if policy.require_fresh && stale {
                continue;
            }
            let score = overlap_score(&query_tokens, &tokenize(&record.content));
            if score >= policy.min_overlap as i64 && score > 0 {
                scored.push((record, score));
            }
        }
        // Score desc, poi source asc per determinismo totale.
        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.source.cmp(&b.0.source)));
        scored.truncate(max_hits);

        let hits = scored
            .into_iter()
            .map(|(record, score)| {
                let excerpt = make_excerpt(&record.content, &query_tokens);
                GroundedHit {
                    record_id: record.id.clone(),
                    source: record.source.clone(),
                    version: record.version.clone(),
                    excerpt,
                    score,
                    stale: record.is_stale_at(now),
                }
            })
            .collect();
        Ok(hits)
    }

    /// Enforcement: almeno `min_hits` citazioni, altrimenti `InsufficientGrounding`.
    ///
    /// Questa è la policy `no-answer-from-memory`: il chiamante (LLM/agent)
    /// deve propagare l'errore all'utente come `INSUFFICIENT_GROUNDING`
    /// invece di generare testo plausibile.
    pub fn require_grounded(
        &self,
        query: &str,
        hits: &[GroundedHit],
        min_hits: usize,
    ) -> KernelResult<Vec<Citation>> {
        if hits.len() < min_hits.max(1) {
            return Err(KernelError::InsufficientGrounding {
                query: query.to_owned(),
                reason: format!(
                    "found {} grounded hit(s), required {} (stale filtered, no memory fallback)",
                    hits.len(),
                    min_hits.max(1)
                ),
            });
        }
        Ok(hits
            .iter()
            .map(|h| Citation {
                record_id: h.record_id.clone(),
                source: h.source.clone(),
                version: h.version.clone(),
                excerpt: h.excerpt.clone(),
            })
            .collect())
    }
}

/// Tool read-only `knowledge.retrieve` per [`crate::dispatcher::AgentKernel`].
///
/// Args JSON: `{ "query": "...", "max_hits"?: u64, "require_fresh"?: bool, "min_hits"?: u64 }`.
/// Su grounding insufficiente fallisce con `InsufficientGrounding` così la
/// saga compensa invece di rispondere con allucinazioni.
pub struct KnowledgeRetrieveTool {
    fabric: Arc<KnowledgeFabric>,
    default_policy: RetrievalPolicy,
}

impl KnowledgeRetrieveTool {
    pub fn new(fabric: Arc<KnowledgeFabric>) -> Self {
        Self {
            fabric,
            default_policy: RetrievalPolicy::default(),
        }
    }

    pub fn with_policy(fabric: Arc<KnowledgeFabric>, policy: RetrievalPolicy) -> Self {
        Self {
            fabric,
            default_policy: policy,
        }
    }
}

#[async_trait::async_trait]
impl TransactionalTool for KnowledgeRetrieveTool {
    fn id(&self) -> &'static str {
        "knowledge.retrieve"
    }

    async fn execute(
        &self,
        _ctx: &ToolContext,
        args: serde_json::Value,
    ) -> Result<ToolOutput, KernelError> {
        let query = args
            .get("query")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: "missing required field 'query' (string)".to_owned(),
            })?;
        if query.trim().is_empty() {
            return Err(KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: "field 'query' must not be empty".to_owned(),
            });
        }
        let mut policy = self.default_policy.clone();
        if let Some(max_hits) = args.get("max_hits").and_then(serde_json::Value::as_u64) {
            policy.max_hits = (max_hits.max(1) as usize).min(25);
        }
        if let Some(require_fresh) = args
            .get("require_fresh")
            .and_then(serde_json::Value::as_bool)
        {
            policy.require_fresh = require_fresh;
        }
        let min_hits = args
            .get("min_hits")
            .and_then(serde_json::Value::as_u64)
            .map(|v| (v.max(1) as usize).min(10))
            .unwrap_or(1);

        let hits = self.fabric.retrieve(query, &policy)?;
        let citations = self
            .fabric
            .require_grounded(query, &hits, min_hits)
            .map_err(|e| {
                // Mappa in ToolExecution con marcatore machine-readable,
                // preservando il messaggio di grounding per l'audit.
                match e {
                    KernelError::InsufficientGrounding { query, reason } => {
                        KernelError::ToolExecution {
                            tool_id: self.id().to_owned(),
                            message: format!("INSUFFICIENT_GROUNDING query='{query}': {reason}"),
                        }
                    }
                    other => other,
                }
            })?;

        Ok(ToolOutput::new(serde_json::json!({
            "query": query,
            "grounded": true,
            "hits": hits,
            "citations": citations,
        }))
        .with_effect(format!("retrieved {} grounded hit(s)", hits.len())))
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: serde_json::Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        // Read-only: nessun effetto da annullare.
        Ok(())
    }
}

// --- Scoring helpers (puri, deterministici) ---

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn overlap_score(query_tokens: &[String], doc_tokens: &[String]) -> i64 {
    if query_tokens.is_empty() || doc_tokens.is_empty() {
        return 0;
    }
    // Conta token query presenti almeno una volta nel documento.
    let mut score: i64 = 0;
    for qt in query_tokens {
        if doc_tokens.iter().any(|dt| dt == qt) {
            score = score.saturating_add(1);
        }
    }
    score
}

fn make_excerpt(content: &str, query_tokens: &[String]) -> String {
    const RADIUS: usize = 140;
    const MAX_LEN: usize = 280;
    let lowered = content.to_ascii_lowercase();
    let mut best: Option<usize> = None;
    for tok in query_tokens {
        if tok.len() < 2 {
            continue;
        }
        if let Some(pos) = lowered.find(tok.as_str()) {
            best = Some(best.map_or(pos, |b| b.min(pos)));
        }
    }
    let excerpt = match best {
        Some(pos) => {
            let start = pos.saturating_sub(RADIUS);
            let end = (pos.saturating_add(RADIUS)).min(content.len());
            // Taglia su boundary UTF-8 validi.
            let mut s = start;
            while s < end && !content.is_char_boundary(s) {
                s = s.saturating_add(1);
            }
            let mut e = end;
            while e > s && !content.is_char_boundary(e) {
                e = e.saturating_sub(1);
            }
            content.get(s..e).unwrap_or(content).trim()
        }
        None => content.trim(),
    };
    // Tronca a MAX_LEN caratteri su boundary.
    if excerpt.len() <= MAX_LEN {
        return excerpt.to_owned();
    }
    let mut end = MAX_LEN;
    while end > 0 && !excerpt.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", excerpt.get(..end).unwrap_or("").trim())
}

#[cfg(test)]
mod unit_tests {
    use super::{make_excerpt, overlap_score, tokenize};

    #[test]
    fn tokenize_skips_short_tokens() {
        assert_eq!(
            tokenize("a refund of €10"),
            vec!["refund".to_owned(), "of".to_owned(), "10".to_owned()]
        );
    }

    #[test]
    fn overlap_counts_query_terms_present() {
        let q = tokenize("refund policy 30 days");
        let d = tokenize("Our refund policy allows returns within 30 days.");
        assert_eq!(overlap_score(&q, &d), 4);
    }

    #[test]
    fn excerpt_contains_match() {
        let out = make_excerpt(
            "Policy: refunds within 30 days of purchase.",
            &tokenize("refunds"),
        );
        assert!(out.contains("refunds"));
    }
}
