//! Gestione rigorosa degli errori del kernel.
//!
//! Nessun `.unwrap()` / `.expect()` nel codice produttivo:
//! ogni fallimento è rappresentato da [`KernelError`].

use thiserror::Error;

/// Errore unificato di SagaShield (WAL + FSM + security + MCP).
#[derive(Debug, Error)]
pub enum KernelError {
    /// Errore SQLite (inclusi vincoli UNIQUE su idempotency_key).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Errore di (de)serializzazione JSON per args/output.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Un tool ha fallito in `execute`.
    #[error("tool execution failed [{tool_id}]: {message}")]
    ToolExecution { tool_id: String, message: String },

    /// Una `compensate` ha fallito durante il rollback.
    #[error("compensation failed [{tool_id}]: {message}")]
    CompensationFailed { tool_id: String, message: String },

    /// Sessione/saga inesistente.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Azione inesistente (id riga).
    #[error("action not found: {0}")]
    ActionNotFound(i64),

    /// Tool non registrato nel registry al momento del rollback.
    #[error("tool not found in registry: {0}")]
    ToolNotFound(String),

    /// Stato persistito non valido (DB corrotto / versione futura).
    #[error("invalid status in db: {0}")]
    InvalidStatus(String),

    /// Mutex del WAL avvelenato (panic in un altro thread).
    #[error("wal lock poisoned: {0}")]
    Lock(String),

    /// Errore I/O (es. stdio del server MCP).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Rollback terminato con almeno una compensazione fallita.
    #[error("rollback partially failed for session {session_id}: {failed} compensation(s) failed")]
    RollbackPartial { session_id: String, failed: usize },

    /// Transizione FSM illegale (guardrail).
    #[error("invalid state transition: cannot apply event '{event}' in state '{current}'")]
    InvalidStateTransition { current: String, event: String },

    /// Violazione generica del security guardrail (Step 0 del kernel).
    #[error("security violation: {0}")]
    SecurityViolation(String),

    /// Path traversal rilevato (tentativo di uscire dalla sandbox con `..`/assoluti/symlink).
    #[error("path traversal detected: {0}")]
    PathTraversalDetected(String),

    /// Accesso a file bloccato dai pattern vietati (es. `.env`, `.git`, chiavi).
    #[error("blocked file access: {0}")]
    BlockedFileAccess(String),

    /// Chiamata di rete verso dominio non in whitelist.
    #[error("unauthorized network access: {0}")]
    UnauthorizedNetworkAccess(String),

    /// Azione irreversibile in attesa di approvazione umana (2-Phase Commit).
    #[error("approval required for irreversible tool '{tool_name}' (token: {token})")]
    ApprovalRequired { tool_name: String, token: String },
}

/// Scorciatoia per i risultati del kernel.
pub type KernelResult<T> = Result<T, KernelError>;
