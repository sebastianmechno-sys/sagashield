//! Contratto dei tool transazionali (Saga Pattern).
//!
//! Ogni tool che produce effetti collaterali deve saperli annullare
//! semanticamente tramite `compensate`.

use serde_json::Value;

use crate::error::KernelResult;
use crate::types::{ToolContext, ToolOutput};

/// Tool eseguibile e compensabile.
///
/// Requisiti:
/// - `Send + Sync + 'static` (dispatcher concorrente su Tokio).
/// - `execute` idempotente su `ctx.idempotency_key`.
/// - `compensate` idempotente, non deve mai andare in panic.
///
/// Nota: `#[async_trait]` rende il trait object-safe (`dyn TransactionalTool`)
/// tramite future boxed — necessario per il registry nel `rollback`.
#[async_trait::async_trait]
pub trait TransactionalTool: Send + Sync + 'static {
    /// ID stabile del tool (es. `"fs.write"`, `"tool_a"`).
    fn id(&self) -> &'static str;

    /// Esegue l'effetto principale.
    async fn execute(
        &self,
        ctx: &ToolContext,
        args: Value,
    ) -> Result<ToolOutput, crate::error::KernelError>;

    /// Annulla semanticamente una `execute` precedentemente riuscita.
    ///
    /// Riceve gli stessi `args` e l'`output` originale per un undo mirato.
    async fn compensate(
        &self,
        ctx: &ToolContext,
        args: Value,
        output: ToolOutput,
    ) -> Result<(), crate::error::KernelError>;

    /// `true` se l'effetto non è compensabile in modo affidabile
    /// (es. invio email, transazione esterna irreversibile).
    ///
    /// Default `false` per retrocompatibilità: i tool irreversibili
    /// richiedono approvazione umana (2-Phase Commit) prima di eseguire.
    fn is_irreversible(&self) -> bool {
        false
    }

    /// Re-export del tipo di risultato per comodità (non obbligatorio).
    #[allow(dead_code)]
    fn _result_type(&self) -> Option<KernelResult<ToolOutput>> {
        None
    }
}
