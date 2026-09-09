//! L4 Memory Vault — memoria persistente, portabile e scopata per agenti.
//!
//! La memoria segue l'utente, non il vendor: stesso vault, N modelli.
//! Isolamento per `(tenant, agent, user_id)` — il cliente A non vede mai B.
//!
//! Scoring deterministico senza embedding esterni:
//! `overlap lessicale + importance + bonus recency`.
//! L'accesso promuove il ricordo (`access_count`, `last_accessed_secs`);
//! `prune_weak` rimuove il rumore mai riusato (decay esplicito, auditabile).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{KernelError, KernelResult};
use crate::knowledge::now_secs;
use crate::traits::TransactionalTool;
use crate::types::{ToolContext, ToolOutput};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS memories (
    id                TEXT PRIMARY KEY,
    tenant            TEXT NOT NULL DEFAULT 'default',
    agent             TEXT NOT NULL DEFAULT 'default',
    user_id           TEXT NOT NULL DEFAULT 'default',
    kind              TEXT NOT NULL DEFAULT 'fact',
    content           TEXT NOT NULL,
    importance        INTEGER NOT NULL DEFAULT 50,
    access_count      INTEGER NOT NULL DEFAULT 0,
    created_at_secs   INTEGER NOT NULL,
    updated_at_secs   INTEGER NOT NULL,
    last_accessed_secs INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories(tenant, agent, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_dedup ON memories(tenant, agent, user_id, content);
"#;

/// Tipo di ricordo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemoryKind {
    /// Fatto stabile (es. `progetto Alpha usa regione EU`).
    #[default]
    Fact,
    /// Preferenza utente (es. `summary settimanali il lunedì`).
    Preference,
    /// Pattern appreso (es. `mostrare esempi prima funziona 3x`).
    Pattern,
}

impl MemoryKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Preference => "preference",
            Self::Pattern => "pattern",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "preference" => Self::Preference,
            "pattern" => Self::Pattern,
            _ => Self::Fact,
        }
    }
}

/// Scope di isolamento multi-tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MemoryScope {
    #[serde(default = "default_scope_part")]
    pub tenant: String,
    #[serde(default = "default_scope_part")]
    pub agent: String,
    #[serde(default = "default_scope_part")]
    pub user_id: String,
}

fn default_scope_part() -> String {
    "default".to_owned()
}

impl MemoryScope {
    pub fn new(
        tenant: impl Into<String>,
        agent: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            agent: agent.into(),
            user_id: user_id.into(),
        }
    }
}

/// Input per `store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMemoryInput {
    #[serde(flatten, default)]
    pub scope: MemoryScope,
    #[serde(default)]
    pub kind: MemoryKind,
    pub content: String,
    /// 0-100. Default 50. Clampato automaticamente.
    pub importance: Option<i64>,
}

/// Record persistito.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub id: String,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
    pub importance: i64,
    pub access_count: i64,
    pub created_at_secs: i64,
    pub updated_at_secs: i64,
    pub last_accessed_secs: i64,
}

/// Hit con score spiegato.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryHit {
    pub memory_id: String,
    pub content: String,
    pub kind: MemoryKind,
    pub score: i64,
    pub access_count: i64,
}

/// Policy di recall (difensiva, deterministica).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallPolicy {
    pub max_hits: usize,
    pub min_overlap: usize,
}

impl Default for RecallPolicy {
    fn default() -> Self {
        Self {
            max_hits: 5,
            min_overlap: 1,
        }
    }
}

/// Vault thread-safe, condivisibile via `Arc`.
pub struct MemoryVault {
    conn: Mutex<Connection>,
}

impl MemoryVault {
    pub fn open(path: impl AsRef<Path>) -> KernelResult<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let vault = Self {
            conn: Mutex::new(conn),
        };
        vault.init_schema()?;
        Ok(vault)
    }

    pub fn open_in_memory() -> KernelResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let vault = Self {
            conn: Mutex::new(conn),
        };
        vault.init_schema()?;
        Ok(vault)
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

    fn clamp_importance(v: Option<i64>) -> i64 {
        v.unwrap_or(50).clamp(0, 100)
    }

    /// Store idempotente: stesso `(scope, content)` ritorna l'ID esistente
    /// (bump di `importance` se maggiore) con `deduped=true`.
    pub fn store(&self, input: NewMemoryInput) -> KernelResult<(String, bool)> {
        let content = input.content.trim().to_owned();
        if content.is_empty() {
            return Err(KernelError::ToolExecution {
                tool_id: "memory.store".to_owned(),
                message: "field 'content' must not be empty".to_owned(),
            });
        }
        let importance = Self::clamp_importance(input.importance);
        let now = now_secs()?;
        let conn = self.lock()?;

        let existing: Option<(String, i64)> = conn
            .query_row(
                "SELECT id, importance FROM memories
                 WHERE tenant = ?1 AND agent = ?2 AND user_id = ?3 AND content = ?4",
                params![
                    input.scope.tenant,
                    input.scope.agent,
                    input.scope.user_id,
                    content
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((id, prev_importance)) = existing {
            let merged = prev_importance.max(importance);
            conn.execute(
                "UPDATE memories SET importance = ?1, updated_at_secs = ?2,
                 last_accessed_secs = ?2 WHERE id = ?3",
                params![merged, now, id],
            )?;
            info!(memory_id = %id, "memory dedup hit");
            return Ok((id, true));
        }

        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO memories
             (id, tenant, agent, user_id, kind, content, importance,
              access_count, created_at_secs, updated_at_secs, last_accessed_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?8, ?8)",
            params![
                id,
                input.scope.tenant,
                input.scope.agent,
                input.scope.user_id,
                input.kind.as_str(),
                content,
                importance,
                now,
            ],
        )?;
        info!(memory_id = %id, "memory stored");
        Ok((id, false))
    }

    pub fn get(&self, id: &str) -> KernelResult<Option<MemoryRecord>> {
        let conn = self.lock()?;
        let row: Option<MemoryRecord> = conn
            .query_row(
                "SELECT id, tenant, agent, user_id, kind, content, importance,
                        access_count, created_at_secs, updated_at_secs, last_accessed_secs
                 FROM memories WHERE id = ?1",
                params![id],
                |r| {
                    let kind_str: String = r.get(4)?;
                    Ok(MemoryRecord {
                        id: r.get(0)?,
                        scope: MemoryScope {
                            tenant: r.get(1)?,
                            agent: r.get(2)?,
                            user_id: r.get(3)?,
                        },
                        kind: MemoryKind::parse(kind_str.as_str()),
                        content: r.get(5)?,
                        importance: r.get(6)?,
                        access_count: r.get(7)?,
                        created_at_secs: r.get(8)?,
                        updated_at_secs: r.get(9)?,
                        last_accessed_secs: r.get(10)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Recall scopato con scoring `overlap*10 + importance/20 + recency`.
    /// Promuove gli hit (`access_count+1`, `last_accessed=now`).
    pub fn recall(
        &self,
        scope: &MemoryScope,
        query: &str,
        policy: &RecallPolicy,
    ) -> KernelResult<Vec<MemoryHit>> {
        let now = now_secs()?;
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, content, importance, access_count,
                    created_at_secs, updated_at_secs, last_accessed_secs
             FROM memories WHERE tenant = ?1 AND agent = ?2 AND user_id = ?3",
        )?;
        let rows = stmt.query_map(params![scope.tenant, scope.agent, scope.user_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(7)?,
            ))
        })?;

        let mut scored: Vec<(String, String, MemoryKind, i64, i64)> = Vec::new();
        for row in rows {
            let (id, kind_str, content, importance, access_count, last_accessed) =
                row.map_err(KernelError::Sqlite)?;
            let overlap = overlap_score(&query_tokens, &tokenize(content.as_str()));
            if overlap < policy.min_overlap as i64 || overlap <= 0 {
                continue;
            }
            let recency_bonus = if now.saturating_sub(last_accessed) <= 86_400 {
                2
            } else if now.saturating_sub(last_accessed) <= 7 * 86_400 {
                1
            } else {
                0
            };
            let score = overlap
                .saturating_mul(10)
                .saturating_add(importance / 20)
                .saturating_add(recency_bonus);
            scored.push((
                id,
                content,
                MemoryKind::parse(kind_str.as_str()),
                score,
                access_count,
            ));
        }
        // Score desc, poi id asc per determinismo totale.
        scored.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));
        scored.truncate(policy.max_hits.max(1));

        // Promozione accessi (stesso lock, niente deadlock).
        for (id, _, _, _, _) in &scored {
            conn.execute(
                "UPDATE memories SET access_count = access_count + 1,
                 last_accessed_secs = ?1 WHERE id = ?2",
                params![now, id],
            )?;
        }

        Ok(scored
            .into_iter()
            .map(|(id, content, kind, score, access_count)| MemoryHit {
                memory_id: id,
                content,
                kind,
                score,
                access_count: access_count.saturating_add(1),
            })
            .collect())
    }

    /// Dimentica un ricordo per ID. Ritorna `true` se esisteva.
    pub fn forget(&self, id: &str) -> KernelResult<bool> {
        let conn = self.lock()?;
        let n = conn.execute("DELETE FROM memories WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Decay esplicito: elimina ricordi deboli (`importance < min_importance`)
    /// mai riusati (`access_count = 0`) e vecchi (`now - updated_at > older_than_secs`).
    pub fn prune_weak(
        &self,
        min_importance: i64,
        older_than_secs: i64,
        now: i64,
    ) -> KernelResult<u64> {
        let conn = self.lock()?;
        let n = conn.execute(
            "DELETE FROM memories WHERE importance < ?1 AND access_count = 0
             AND (?2 - updated_at_secs) > ?3",
            params![min_importance, now, older_than_secs],
        )?;
        Ok(n as u64)
    }
}

/// Tool `memory.store` — compensabile con `forget` (undo semantico).
pub struct MemoryStoreTool {
    vault: Arc<MemoryVault>,
}

impl MemoryStoreTool {
    pub fn new(vault: Arc<MemoryVault>) -> Self {
        Self { vault }
    }
}

#[async_trait::async_trait]
impl TransactionalTool for MemoryStoreTool {
    fn id(&self) -> &'static str {
        "memory.store"
    }

    async fn execute(
        &self,
        _ctx: &ToolContext,
        args: serde_json::Value,
    ) -> Result<ToolOutput, KernelError> {
        let content = args
            .get("content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KernelError::ToolExecution {
                tool_id: self.id().to_owned(),
                message: "missing required field 'content' (string)".to_owned(),
            })?;
        let scope = MemoryScope {
            tenant: args
                .get("tenant")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
            agent: args
                .get("agent")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
            user_id: args
                .get("user_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
        };
        let kind = args
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .map(MemoryKind::parse)
            .unwrap_or_default();
        let importance = args.get("importance").and_then(serde_json::Value::as_i64);
        let (id, deduped) = self.vault.store(NewMemoryInput {
            scope,
            kind,
            content: content.to_owned(),
            importance,
        })?;
        Ok(ToolOutput::new(serde_json::json!({
            "memory_id": id,
            "deduped": deduped,
        }))
        .with_effect(format!("stored memory {id}")))
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: serde_json::Value,
        output: ToolOutput,
    ) -> Result<(), KernelError> {
        // Undo: cancella solo se creato da questo step (non dedup).
        let deduped = output
            .data
            .get("deduped")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if deduped {
            return Ok(());
        }
        if let Some(id) = output
            .data
            .get("memory_id")
            .and_then(serde_json::Value::as_str)
        {
            let _ = self.vault.forget(id)?;
        }
        Ok(())
    }
}

/// Tool `memory.recall` — read-only.
pub struct MemoryRecallTool {
    vault: Arc<MemoryVault>,
}

impl MemoryRecallTool {
    pub fn new(vault: Arc<MemoryVault>) -> Self {
        Self { vault }
    }
}

#[async_trait::async_trait]
impl TransactionalTool for MemoryRecallTool {
    fn id(&self) -> &'static str {
        "memory.recall"
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
        let scope = MemoryScope {
            tenant: args
                .get("tenant")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
            agent: args
                .get("agent")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
            user_id: args
                .get("user_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("default")
                .to_owned(),
        };
        let mut policy = RecallPolicy::default();
        if let Some(max_hits) = args.get("max_hits").and_then(serde_json::Value::as_u64) {
            policy.max_hits = (max_hits.max(1) as usize).min(25);
        }
        let hits = self.vault.recall(&scope, query, &policy)?;
        Ok(ToolOutput::new(serde_json::json!({
            "query": query,
            "count": hits.len(),
            "hits": hits,
        }))
        .with_effect(format!("recalled {} memories", hits.len())))
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

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn overlap_score(query_tokens: &[String], doc_tokens: &[String]) -> i64 {
    let mut score: i64 = 0;
    for qt in query_tokens {
        if doc_tokens.iter().any(|dt| dt == qt) {
            score = score.saturating_add(1);
        }
    }
    score
}

#[cfg(test)]
mod unit_tests {
    use super::overlap_score;
    use super::tokenize;

    #[test]
    fn recall_scoring_counts_overlap() {
        let q = tokenize("weekly summaries monday");
        let d = tokenize("user prefers weekly summaries on monday");
        assert_eq!(overlap_score(&q, &d), 3);
    }
}
