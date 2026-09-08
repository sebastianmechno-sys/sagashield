//! Tipi fondamentali del kernel (Fase 1).
//!
//! - [`ToolContext`]: identità di una esecuzione.
//! - [`ToolOutput`]: output normalizzato dei tool.
//! - [`ActionStatus`]: PENDING / COMMITTED / COMPENSATED / FAILED.
//! - [`PersistedAction`]: riga della tabella `actions`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::KernelError;

/// Contesto di una singola esecuzione di tool.
///
/// `idempotency_key` è UNIQUE nel WAL e rende i retry sicuri:
/// lo stesso step riloggato con la stessa chiave non duplica effetti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolContext {
    /// ID della sessione/saga (una task utente).
    pub session_id: String,
    /// Posizione dello step nella saga (0, 1, 2, ...).
    pub step_seq: u64,
    /// ID del tool (es. `"tool_a"`).
    pub tool_id: String,
    /// Chiave di idempotenza (`session_id:step_seq:tool_id` di default).
    pub idempotency_key: String,
}

impl ToolContext {
    /// Crea un contesto con chiave di idempotenza deterministica.
    pub fn new(session_id: impl Into<String>, step_seq: u64, tool_id: impl Into<String>) -> Self {
        let session_id = session_id.into();
        let tool_id = tool_id.into();
        let idempotency_key = format!("{session_id}:{step_seq}:{tool_id}");
        Self {
            session_id,
            step_seq,
            tool_id,
            idempotency_key,
        }
    }
}

/// Output normalizzato di un tool dopo `execute` riuscita.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Payload strutturato del tool.
    pub data: Value,
    /// Descrizione human-readable degli effetti collaterali.
    #[serde(default)]
    pub effects: Vec<String>,
}

impl ToolOutput {
    /// Costruttore rapido.
    pub fn new(data: Value) -> Self {
        Self {
            data,
            effects: Vec::new(),
        }
    }

    /// Aggiunge un effetto (builder).
    pub fn with_effect(mut self, effect: impl Into<String>) -> Self {
        self.effects.push(effect.into());
        self
    }
}

/// Stato persistito di una azione nel WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    /// Loggata ma non ancora eseguita / confermata.
    #[serde(rename = "PENDING")]
    Pending,
    /// `execute` riuscita e confermata.
    #[serde(rename = "COMMITTED")]
    Committed,
    /// Compensata con successo durante il rollback.
    #[serde(rename = "COMPENSATED")]
    Compensated,
    /// Fallita: `execute` fallita oppure `compensate` fallita.
    #[serde(rename = "FAILED")]
    Failed,
    /// In attesa di approvazione umana (2-Phase Commit, v0.3).
    #[serde(rename = "PENDING_APPROVAL")]
    PendingApproval,
}

impl ActionStatus {
    /// Rappresentazione canonica persistita su SQLite.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Committed => "COMMITTED",
            Self::Compensated => "COMPENSATED",
            Self::Failed => "FAILED",
            Self::PendingApproval => "PENDING_APPROVAL",
        }
    }

    /// Parsing rigoroso (nessun default silenzioso).
    pub fn parse(s: &str) -> Result<Self, KernelError> {
        match s {
            "PENDING" => Ok(Self::Pending),
            "COMMITTED" => Ok(Self::Committed),
            "COMPENSATED" => Ok(Self::Compensated),
            "FAILED" => Ok(Self::Failed),
            "PENDING_APPROVAL" => Ok(Self::PendingApproval),
            other => Err(KernelError::InvalidStatus(other.to_owned())),
        }
    }
}

impl std::fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ActionStatus {
    type Err = KernelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Riga della tabella `actions` (WAL).
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedAction {
    /// Row id SQLite (`AUTOINCREMENT`).
    pub id: i64,
    /// Sessione di appartenenza.
    pub session_id: String,
    /// Sequenza nello saga.
    pub step_seq: u64,
    /// ID del tool.
    pub tool_id: String,
    /// Chiave di idempotenza (UNIQUE).
    pub idempotency_key: String,
    /// Argomenti originali (JSON).
    pub args: Value,
    /// Output su COMMIT (JSON), `None` finché non committato.
    pub output: Option<ToolOutput>,
    /// Stato corrente.
    pub status: ActionStatus,
    /// Messaggio di errore su FAIL.
    pub error: Option<String>,
    /// Timestamp di creazione riga (SQLite `CURRENT_TIMESTAMP`, UTC).
    pub created_at: String,
    /// Timestamp ultimo aggiornamento (SQLite `CURRENT_TIMESTAMP`, UTC).
    pub updated_at: String,
}

/// Riga della tabella `dead_letter_queue` (compensazioni fallite, v0.3).
///
/// Una entry nasce quando una `compensate()` fallisce durante il rollback:
/// il ciclo LIFO **non** si interrompe (cascading rollback) e l'azione
/// orfana resta qui come `UNRESOLVED` per intervento SRE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DlqEntry {
    /// ID univoco (UUID v4).
    pub id: String,
    /// Sessione di appartenenza.
    pub session_id: String,
    /// Row id dell'azione in `actions` (come testo).
    pub action_id: String,
    /// Tool la cui compensazione è fallita.
    pub tool_name: String,
    /// Argomenti originali (JSON).
    pub params: Value,
    /// Stato dell'azione al momento del fallimento (es. `COMMITTED`).
    pub state: String,
    /// Dettaglio dell'errore di compensazione.
    pub error_message: Option<String>,
    /// `UNRESOLVED` finché un operatore non la gestisce.
    pub status: String,
    /// Tentativi di retry manuali registrati.
    pub retry_count: i64,
    /// Timestamp di creazione (SQLite `CURRENT_TIMESTAMP`, UTC).
    pub created_at: String,
}

/// Report di `Wal::prune_history` (retention engine, v0.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Sessioni terminali eliminate.
    pub sessions_deleted: u64,
    /// Righe `actions` eliminate con le loro sessioni.
    pub actions_deleted: u64,
}
