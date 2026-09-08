//! Write-Ahead Log (WAL) su SQLite — Saga Pattern (Fase 1).
//!
//! Tabelle:
//! - `sessions(id PK, created_at, status)`
//! - `actions(id, session_id, step_seq, tool_id, idempotency_key UNIQUE, ...)`
//!
//! Il [`Wal::rollback`] scorre a ritroso (LIFO) tutte le azioni `COMMITTED`,
//! invoca `compensate()` e aggiorna lo stato in `COMPENSATED` o `FAILED`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use tracing::{info, warn};

use crate::error::{KernelError, KernelResult};
use crate::traits::TransactionalTool;
use crate::types::{ActionStatus, DlqEntry, PersistedAction, PruneReport, ToolContext, ToolOutput};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    status      TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE TABLE IF NOT EXISTS actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    step_seq        INTEGER NOT NULL,
    tool_id         TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    args            TEXT NOT NULL,
    output          TEXT,
    status          TEXT NOT NULL,
    error           TEXT,
    created_at      TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at      TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    UNIQUE (session_id, step_seq)
);
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id, step_seq);
-- Anti-retry: lookup idempotente per (sessione, chiave chiamante).
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_idempotency ON actions(session_id, idempotency_key);
-- Dead Letter Queue: compensazioni fallite (cascading rollback non si ferma).
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    action_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    params          TEXT NOT NULL,
    state           TEXT NOT NULL,
    error_message   TEXT,
    status          TEXT NOT NULL DEFAULT 'UNRESOLVED',
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP)
);
CREATE INDEX IF NOT EXISTS idx_dlq_status ON dead_letter_queue(status);
"#;

/// Motore WAL. Thread-safe (`Mutex<Connection>`), condivisibile via `Arc`.
pub struct Wal {
    conn: Mutex<Connection>,
}

impl Wal {
    /// Apre (o crea) il WAL su file, abilita `journal_mode=WAL` best-effort.
    pub fn open(path: impl AsRef<Path>) -> KernelResult<Self> {
        let conn = Connection::open(path)?;
        // Concorrenza: su lock contention attende fino a 5s invece di
        // fallire subito con `SQLITE_BUSY / database is locked`.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // Best-effort: su alcuni FS può fallire, non deve bloccare l'apertura.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let wal = Self {
            conn: Mutex::new(conn),
        };
        wal.init_schema()?;
        Ok(wal)
    }

    /// WAL in-memory (ideale per i test).
    pub fn open_in_memory() -> KernelResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let wal = Self {
            conn: Mutex::new(conn),
        };
        wal.init_schema()?;
        Ok(wal)
    }

    /// Crea le tabelle `sessions` e `actions` se non esistono.
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

    /// Crea una sessione (idempotente: `INSERT OR IGNORE`).
    pub fn create_session(&self, session_id: &str) -> KernelResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO sessions(id) VALUES (?1)",
            params![session_id],
        )?;
        Ok(())
    }

    /// Registra un'azione come `PENDING`. Ritorna il row id.
    pub fn log_action(&self, ctx: &ToolContext, args: &Value) -> KernelResult<i64> {
        self.log_with_status(ctx, args, ActionStatus::Pending)
    }

    /// Registra un'azione irreversibile come `PENDING_APPROVAL` (2-Phase Commit).
    pub fn log_pending_approval(&self, ctx: &ToolContext, args: &Value) -> KernelResult<i64> {
        self.log_with_status(ctx, args, ActionStatus::PendingApproval)
    }

    fn log_with_status(
        &self,
        ctx: &ToolContext,
        args: &Value,
        status: ActionStatus,
    ) -> KernelResult<i64> {
        self.create_session(&ctx.session_id)?;
        let args_json = serde_json::to_string(args)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO actions(session_id, step_seq, tool_id, idempotency_key, args, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ctx.session_id,
                ctx.step_seq as i64,
                ctx.tool_id,
                ctx.idempotency_key,
                args_json,
                status.as_str(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Marca l'azione come `COMMITTED` con output.
    pub fn mark_committed(&self, action_id: i64, output: &ToolOutput) -> KernelResult<()> {
        let output_json = serde_json::to_string(output)?;
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE actions SET output = ?1, status = 'COMMITTED', error = NULL,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![output_json, action_id],
        )?;
        if n == 0 {
            return Err(KernelError::ActionNotFound(action_id));
        }
        Ok(())
    }

    /// Marca l'azione come `FAILED` (execute fallita).
    pub fn mark_failed(&self, action_id: i64, err_msg: &str) -> KernelResult<()> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE actions SET status = 'FAILED', error = ?1,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![err_msg, action_id],
        )?;
        if n == 0 {
            return Err(KernelError::ActionNotFound(action_id));
        }
        Ok(())
    }

    /// Marca l'azione come `COMPENSATED`.
    pub fn mark_compensated(&self, action_id: i64) -> KernelResult<()> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE actions SET status = 'COMPENSATED', error = NULL,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![action_id],
        )?;
        if n == 0 {
            return Err(KernelError::ActionNotFound(action_id));
        }
        Ok(())
    }

    /// Marca l'azione come `FAILED` dopo compensazione fallita.
    pub fn mark_compensation_failed(&self, action_id: i64, err_msg: &str) -> KernelResult<()> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE actions SET status = 'FAILED', error = ?1,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![err_msg, action_id],
        )?;
        if n == 0 {
            return Err(KernelError::ActionNotFound(action_id));
        }
        Ok(())
    }

    /// Tutte le azioni di una sessione in ordine crescente (`step_seq ASC`).
    pub fn get_actions(&self, session_id: &str) -> KernelResult<Vec<PersistedAction>> {
        let rows: Vec<RawRow> = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare(
                "SELECT id, session_id, step_seq, tool_id, idempotency_key,
                        args, output, status, error, created_at, updated_at
                 FROM actions WHERE session_id = ?1 ORDER BY step_seq ASC",
            )?;
            let mapped = stmt.query_map(params![session_id], RawRow::from_row)?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r?);
            }
            out
        };
        rows.into_iter().map(RawRow::into_action).collect()
    }

    /// Azioni `COMMITTED` in ordine inverso (LIFO) per il rollback.
    fn committed_desc(&self, session_id: &str) -> KernelResult<Vec<PersistedAction>> {
        let rows: Vec<RawRow> = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare(
                "SELECT id, session_id, step_seq, tool_id, idempotency_key,
                        args, output, status, error, created_at, updated_at
                 FROM actions
                 WHERE session_id = ?1 AND status = 'COMMITTED'
                 ORDER BY step_seq DESC",
            )?;
            let mapped = stmt.query_map(params![session_id], RawRow::from_row)?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r?);
            }
            out
        };
        rows.into_iter().map(RawRow::into_action).collect()
    }

    fn session_exists(&self, session_id: &str) -> KernelResult<bool> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Rollback Saga: LIFO su tutte le `COMMITTED`, `compensate()` deterministica.
    ///
    /// - Ordine inverso rispetto all'esecuzione (`step_seq DESC`).
    /// - Stato finale per step: `COMPENSATED` su successo, `FAILED` su errore.
    /// - Se almeno una compensazione fallisce ritorna `RollbackPartial`
    ///   (le altre vengono comunque tentate tutte).
    pub async fn rollback(
        &self,
        session_id: &str,
        registry: &HashMap<String, Arc<dyn TransactionalTool>>,
    ) -> KernelResult<()> {
        // Span OTel: attributi pronti per tracing-opentelemetry / collector.
        let span = tracing::info_span!(
            "agent.saga.rollback",
            "agent.session_id" = %session_id,
            "agent.rollback.triggered" = true,
        );
        let _span_guard = span.enter();

        if !self.session_exists(session_id)? {
            return Err(KernelError::SessionNotFound(session_id.to_owned()));
        }

        let committed = self.committed_desc(session_id)?;
        if committed.is_empty() {
            info!(session_id = %session_id, "rollback: nothing to compensate");
            return Ok(());
        }

        info!(
            session_id = %session_id,
            steps = committed.len(),
            "rollback: starting LIFO compensation"
        );

        let mut failed: usize = 0;

        for action in committed {
            let ctx = ToolContext {
                session_id: action.session_id.clone(),
                step_seq: action.step_seq,
                tool_id: action.tool_id.clone(),
                idempotency_key: action.idempotency_key.clone(),
            };

            let Some(tool) = registry.get(&action.tool_id) else {
                let msg = format!("tool '{}' not in registry", action.tool_id);
                warn!(session_id = %session_id, tool_id = %action.tool_id, "rollback: {msg}");
                self.mark_compensation_failed(action.id, &msg)?;
                self.record_dlq(session_id, &action, &msg)?;
                failed += 1;
                continue;
            };

            let Some(output) = action.output.clone() else {
                let msg = "committed action without output (db inconsistent)".to_owned();
                warn!(session_id = %session_id, tool_id = %action.tool_id, "rollback: {msg}");
                self.mark_compensation_failed(action.id, &msg)?;
                self.record_dlq(session_id, &action, &msg)?;
                failed += 1;
                continue;
            };

            match tool.compensate(&ctx, action.args.clone(), output).await {
                Ok(()) => {
                    info!(
                        session_id = %session_id,
                        tool_id = %action.tool_id,
                        seq = action.step_seq,
                        "rollback: compensated"
                    );
                    self.mark_compensated(action.id)?;
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        tool_id = %action.tool_id,
                        seq = action.step_seq,
                        error = %e,
                        "rollback: compensation failed → DLQ"
                    );
                    let msg = e.to_string();
                    self.mark_compensation_failed(action.id, &msg)?;
                    // Cascading rollback: il ciclo NON si interrompe,
                    // l'orfana va in DLQ come UNRESOLVED.
                    self.record_dlq(session_id, &action, &msg)?;
                    failed += 1;
                }
            }
        }

        if failed > 0 {
            // Non blocca il sistema: la sessione resta tracciata con DLQ.
            if let Err(e) = self.set_session_status(session_id, "RECOVERED_WITH_DLQ") {
                warn!(session_id = %session_id, error = %e, "rollback: session mark failed");
            }
            Err(KernelError::RollbackPartial {
                session_id: session_id.to_owned(),
                failed,
            })
        } else {
            info!(session_id = %session_id, "rollback: completed");
            Ok(())
        }
    }

    /// Stato della sessione (`None` se inesistente).
    pub fn session_status(&self, session_id: &str) -> KernelResult<Option<String>> {
        let conn = self.lock()?;
        match conn.query_row(
            "SELECT status FROM sessions WHERE id = ?1",
            params![session_id],
            |row| row.get(0),
        ) {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_session_status(&self, session_id: &str, status: &str) -> KernelResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE sessions SET status = ?1 WHERE id = ?2",
            params![status, session_id],
        )?;
        Ok(())
    }

    /// Lookup anti-retry: azione con `(sessione, chiave)` se esiste.
    ///
    /// Usata dal kernel per lo short-circuit idempotente: una `COMMITTED`
    /// ritrovata permette di restituire l'output cachato senza rieseguire.
    pub fn find_by_idempotency_key(
        &self,
        session_id: &uuid::Uuid,
        key: &str,
    ) -> KernelResult<Option<PersistedAction>> {
        let sid = session_id.to_string();
        let row: Option<RawRow> = {
            let conn = self.lock()?;
            conn.query_row(
                "SELECT id, session_id, step_seq, tool_id, idempotency_key,
                        args, output, status, error, created_at, updated_at
                 FROM actions WHERE session_id = ?1 AND idempotency_key = ?2",
                params![sid, key],
                RawRow::from_row,
            )
            .optional()?
        };
        row.map(RawRow::into_action).transpose()
    }

    /// Durata della saga in secondi (julianday su created/updated_at).
    /// `None` se la sessione non ha azioni.
    pub fn session_duration_secs(&self, session_id: &str) -> KernelResult<Option<f64>> {
        let conn = self.lock()?;
        let secs: Option<f64> = conn.query_row(
            "SELECT (julianday(MAX(updated_at)) - julianday(MIN(created_at))) * 86400.0
             FROM actions WHERE session_id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(secs)
    }

    /// Registra una compensazione fallita in Dead Letter Queue (`UNRESOLVED`).
    pub fn record_dlq(
        &self,
        session_id: &str,
        action: &PersistedAction,
        error_msg: &str,
    ) -> KernelResult<()> {
        let params_json = serde_json::to_string(&action.args)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO dead_letter_queue(
                 id, session_id, action_id, tool_name, params,
                 state, error_message, status, retry_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'UNRESOLVED', 0)",
            params![
                uuid::Uuid::new_v4().to_string(),
                session_id,
                action.id.to_string(),
                action.tool_id,
                params_json,
                action.status.as_str(),
                error_msg,
            ],
        )?;
        warn!(
            session_id = %session_id,
            tool_id = %action.tool_id,
            seq = action.step_seq,
            "dlq: recorded UNRESOLVED entry"
        );
        Ok(())
    }

    /// Tutte le entry DLQ ancora `UNRESOLVED` (per SRE / MCP inspect).
    pub fn get_unresolved_dlq(&self) -> KernelResult<Vec<DlqEntry>> {
        let rows: Vec<DlqRow> = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare(
                "SELECT id, session_id, action_id, tool_name, params,
                        state, error_message, status, retry_count, created_at
                 FROM dead_letter_queue WHERE status = 'UNRESOLVED'
                 ORDER BY created_at, id",
            )?;
            let mapped = stmt.query_map([], DlqRow::from_row)?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r?);
            }
            out
        };
        rows.into_iter().map(DlqRow::into_entry).collect()
    }

    /// Azione `PENDING_APPROVAL` più recente di (sessione, tool), se esiste.
    pub fn find_pending_approval(
        &self,
        session_id: &str,
        tool_id: &str,
    ) -> KernelResult<Option<PersistedAction>> {
        let row: Option<RawRow> = {
            let conn = self.lock()?;
            conn.query_row(
                "SELECT id, session_id, step_seq, tool_id, idempotency_key,
                        args, output, status, error, created_at, updated_at
                 FROM actions
                 WHERE session_id = ?1 AND tool_id = ?2 AND status = 'PENDING_APPROVAL'
                 ORDER BY step_seq DESC LIMIT 1",
                params![session_id, tool_id],
                RawRow::from_row,
            )
            .optional()?
        };
        row.map(RawRow::into_action).transpose()
    }

    /// Retention: elimina sessioni terminali vecchie e le loro azioni.
    ///
    /// Rimuove solo sessioni marcate `RECOVERED` / `RECOVERED_WITH_DLQ` con
    /// `created_at` più vecchia di `older_than_days` giorni. Le entry DLQ
    /// `UNRESOLVED` non vengono **mai** toccate (audit e SRE).
    pub fn prune_history(&self, older_than_days: u32) -> KernelResult<PruneReport> {
        let modifier = format!("-{older_than_days} days");
        let (sessions_deleted, actions_deleted) = {
            let conn = self.lock()?;
            let actions_deleted = conn.execute(
                "DELETE FROM actions WHERE session_id IN (
                     SELECT id FROM sessions
                     WHERE status IN ('RECOVERED','RECOVERED_WITH_DLQ')
                       AND created_at < datetime('now', ?1)
                 )",
                params![modifier],
            )?;
            let sessions_deleted = conn.execute(
                "DELETE FROM sessions
                 WHERE status IN ('RECOVERED','RECOVERED_WITH_DLQ')
                   AND created_at < datetime('now', ?1)",
                params![modifier],
            )?;
            (sessions_deleted, actions_deleted)
        };
        // Cast checked: niente troncamento silenzioso su 32 bit.
        let report = PruneReport {
            sessions_deleted: u64::try_from(sessions_deleted)
                .map_err(|_| KernelError::InvalidStatus("prune count overflow".to_owned()))?,
            actions_deleted: u64::try_from(actions_deleted)
                .map_err(|_| KernelError::InvalidStatus("prune count overflow".to_owned()))?,
        };
        info!(
            sessions = report.sessions_deleted,
            actions = report.actions_deleted,
            older_than_days,
            "retention: pruned terminal history"
        );
        Ok(report)
    }

    /// Reclama spazio su disco dopo il pruning.
    pub fn vacuum(&self) -> KernelResult<()> {
        let conn = self.lock()?;
        conn.execute_batch("VACUUM;")?;
        Ok(())
    }

    /// Crash recovery: compensa le sessioni orfane e ritorna i loro ID.
    ///
    /// Una sessione è "dangling" se ha azioni `PENDING` (crash tra log ed
    /// execute) o `COMMITTED` mai finalizzate (crash prima del completamento
    /// o del rollback). Per ciascuna:
    /// - i `PENDING` orfani diventano `FAILED` (mai eseguiti: niente compensate);
    /// - i `COMMITTED` orfani vengono compensati in LIFO via [`Wal::rollback`];
    /// - la sessione è marcata `RECOVERED` (o `RECOVERED_WITH_DLQ` se qualche
    ///   compensazione fallisce e finisce in DLQ, senza bloccare le altre).
    pub async fn recover_dangling(
        &self,
        registry: &HashMap<String, Arc<dyn TransactionalTool>>,
    ) -> KernelResult<Vec<String>> {
        let dangling: Vec<String> = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare(
                "SELECT DISTINCT session_id FROM actions
                 WHERE status IN ('PENDING','COMMITTED') ORDER BY session_id",
            )?;
            let mapped = stmt.query_map([], |row| row.get(0))?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r?);
            }
            out
        };

        if dangling.is_empty() {
            info!("recovery: no dangling sessions");
            return Ok(Vec::new());
        }
        info!(count = dangling.len(), "recovery: found dangling sessions");

        let mut recovered = Vec::new();
        for session_id in dangling {
            // PENDING orfani: interrotti dal crash, mai confermati.
            let pendings: Vec<i64> = {
                let conn = self.lock()?;
                let mut stmt = conn.prepare(
                    "SELECT id FROM actions
                     WHERE session_id = ?1 AND status = 'PENDING' ORDER BY step_seq",
                )?;
                let mapped = stmt.query_map(params![session_id], |row| row.get(0))?;
                let mut out = Vec::new();
                for r in mapped {
                    out.push(r?);
                }
                out
            };
            for action_id in pendings {
                self.mark_failed(
                    action_id,
                    "orphaned PENDING: process crashed before execute finished (recovered)",
                )?;
            }

            // COMMITTED orfani: rollback LIFO (le compensate fallite
            // finiscono in DLQ, la sessione resta marcata con DLQ).
            let status = match self.rollback(&session_id, registry).await {
                Ok(()) => "RECOVERED",
                Err(KernelError::RollbackPartial { failed, .. }) => {
                    warn!(
                        session_id = %session_id,
                        failed,
                        "recovery: partial compensation, session flagged with DLQ"
                    );
                    "RECOVERED_WITH_DLQ"
                }
                Err(e) => return Err(e),
            };
            self.set_session_status(&session_id, status)?;
            info!(session_id = %session_id, status, "recovery: session recovered");
            recovered.push(session_id);
        }
        Ok(recovered)
    }
}

/// Riga grezza da SQLite, convertita poi in [`PersistedAction`] senza `unwrap`.
struct RawRow {
    id: i64,
    session_id: String,
    step_seq_i64: i64,
    tool_id: String,
    idempotency_key: String,
    args_json: String,
    output_json: Option<String>,
    status_str: String,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl RawRow {
    fn from_row(row: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            step_seq_i64: row.get(2)?,
            tool_id: row.get(3)?,
            idempotency_key: row.get(4)?,
            args_json: row.get(5)?,
            output_json: row.get(6)?,
            status_str: row.get(7)?,
            error: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }

    fn into_action(self) -> KernelResult<PersistedAction> {
        let step_seq = u64::try_from(self.step_seq_i64).map_err(|_| {
            KernelError::InvalidStatus(format!("negative step_seq {}", self.step_seq_i64))
        })?;
        let args: Value = serde_json::from_str(&self.args_json)?;
        let output: Option<ToolOutput> = match self.output_json {
            Some(s) => Some(serde_json::from_str(&s)?),
            None => None,
        };
        let status = ActionStatus::parse(&self.status_str)?;
        Ok(PersistedAction {
            id: self.id,
            session_id: self.session_id,
            step_seq,
            tool_id: self.tool_id,
            idempotency_key: self.idempotency_key,
            args,
            output,
            status,
            error: self.error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Riga grezza da `dead_letter_queue`, convertita in [`DlqEntry`].
struct DlqRow {
    id: String,
    session_id: String,
    action_id: String,
    tool_name: String,
    params_json: String,
    state: String,
    error_message: Option<String>,
    status: String,
    retry_count: i64,
    created_at: String,
}

impl DlqRow {
    fn from_row(row: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            action_id: row.get(2)?,
            tool_name: row.get(3)?,
            params_json: row.get(4)?,
            state: row.get(5)?,
            error_message: row.get(6)?,
            status: row.get(7)?,
            retry_count: row.get(8)?,
            created_at: row.get(9)?,
        })
    }

    fn into_entry(self) -> KernelResult<DlqEntry> {
        let params: Value = serde_json::from_str(&self.params_json)?;
        Ok(DlqEntry {
            id: self.id,
            session_id: self.session_id,
            action_id: self.action_id,
            tool_name: self.tool_name,
            params,
            state: self.state,
            error_message: self.error_message,
            status: self.status,
            retry_count: self.retry_count,
            created_at: self.created_at,
        })
    }
}
