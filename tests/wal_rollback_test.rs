//! Test end-to-end Fase 1: WAL & Rollback (Saga LIFO).
//!
//! Scenario: ToolA OK → ToolB OK → ToolC CRASH.
//! Atteso: rollback in ordine inverso (prima B, poi A),
//! DB finale: A=COMPENSATED, B=COMPENSATED, C=FAILED.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sagashield::{KernelError, ToolContext, ToolOutput, TransactionalTool, Wal};
use serde_json::{Value, json};

/// Tool fittizio con flag di fallimento e tracciamento compensazioni.
struct MockTool {
    id: &'static str,
    fail_execute: bool,
    fail_compensate: bool,
    compensate_order: Arc<Mutex<Vec<String>>>,
}

impl MockTool {
    fn new(
        id: &'static str,
        fail_execute: bool,
        fail_compensate: bool,
        order: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            id,
            fail_execute,
            fail_compensate,
            compensate_order: order,
        }
    }
}

#[async_trait::async_trait]
impl TransactionalTool for MockTool {
    fn id(&self) -> &'static str {
        self.id
    }

    async fn execute(&self, ctx: &ToolContext, _args: Value) -> Result<ToolOutput, KernelError> {
        if self.fail_execute {
            return Err(KernelError::ToolExecution {
                tool_id: self.id.to_owned(),
                message: format!("simulated crash at seq {}", ctx.step_seq),
            });
        }
        Ok(
            ToolOutput::new(json!({ "tool": self.id, "seq": ctx.step_seq }))
                .with_effect(format!("executed {}", self.id)),
        )
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        // Traccia l'ordine (poison-safe: usa il contenuto anche se avvelenato).
        match self.compensate_order.lock() {
            Ok(mut g) => g.push(self.id.to_owned()),
            Err(poisoned) => poisoned.into_inner().push(self.id.to_owned()),
        }
        if self.fail_compensate {
            return Err(KernelError::CompensationFailed {
                tool_id: self.id.to_owned(),
                message: "simulated compensation failure".to_owned(),
            });
        }
        Ok(())
    }
}

/// Esegue uno step con logging WAL: PENDING → COMMITTED | FAILED.
async fn run_step(
    wal: &Wal,
    tool: &Arc<dyn TransactionalTool>,
    session_id: &str,
    seq: u64,
    args: Value,
) -> Result<Option<ToolOutput>, KernelError> {
    let ctx = ToolContext::new(session_id, seq, tool.id());
    let action_id = wal.log_action(&ctx, &args)?;
    match tool.execute(&ctx, args).await {
        Ok(output) => {
            wal.mark_committed(action_id, &output)?;
            Ok(Some(output))
        }
        Err(e) => {
            wal.mark_failed(action_id, &e.to_string())?;
            Err(e)
        }
    }
}

#[tokio::test]
async fn rollback_compensates_lifo_after_crash() -> Result<(), KernelError> {
    let wal = Wal::open_in_memory()?;
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    wal.create_session(&session_id)?;

    let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let tool_a: Arc<dyn TransactionalTool> =
        Arc::new(MockTool::new("tool_a", false, false, Arc::clone(&order)));
    let tool_b: Arc<dyn TransactionalTool> =
        Arc::new(MockTool::new("tool_b", false, false, Arc::clone(&order)));
    let tool_c: Arc<dyn TransactionalTool> =
        Arc::new(MockTool::new("tool_c", true, false, Arc::clone(&order)));

    let mut registry: HashMap<String, Arc<dyn TransactionalTool>> = HashMap::new();
    registry.insert("tool_a".to_owned(), Arc::clone(&tool_a));
    registry.insert("tool_b".to_owned(), Arc::clone(&tool_b));
    registry.insert("tool_c".to_owned(), Arc::clone(&tool_c));

    // ToolA (successo), ToolB (successo), ToolC (crash simulato).
    let out_a = run_step(&wal, &tool_a, &session_id, 0, json!({"v": "a"})).await?;
    assert!(out_a.is_some(), "ToolA deve avere successo");

    let out_b = run_step(&wal, &tool_b, &session_id, 1, json!({"v": "b"})).await?;
    assert!(out_b.is_some(), "ToolB deve avere successo");

    let err_c = run_step(&wal, &tool_c, &session_id, 2, json!({"v": "c"}))
        .await
        .expect_err("ToolC deve fallire (crash simulato)");
    assert!(
        matches!(err_c, KernelError::ToolExecution { .. }),
        "ToolC deve fallire con ToolExecution, ottenuto: {err_c}"
    );

    // Rollback: deve compensare in LIFO (prima B, poi A).
    wal.rollback(&session_id, &registry).await?;

    let compensated: Vec<String> = order
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|p| p.into_inner().clone());
    assert_eq!(
        compensated,
        vec!["tool_b".to_owned(), "tool_a".to_owned()],
        "ordine LIFO atteso [tool_b, tool_a], ottenuto {compensated:?}"
    );
    assert!(
        !compensated.contains(&"tool_c".to_owned()),
        "tool_c non committato → mai compensato"
    );

    // Verifica stato finale su SQLite.
    let actions = wal.get_actions(&session_id)?;
    assert_eq!(actions.len(), 3, "attese 3 azioni nel WAL");

    assert_eq!(actions[0].tool_id, "tool_a");
    assert_eq!(
        actions[0].status,
        sagashield::ActionStatus::Compensated,
        "ToolA deve essere COMPENSATED"
    );
    assert!(actions[0].output.is_some());

    assert_eq!(actions[1].tool_id, "tool_b");
    assert_eq!(
        actions[1].status,
        sagashield::ActionStatus::Compensated,
        "ToolB deve essere COMPENSATED"
    );

    assert_eq!(actions[2].tool_id, "tool_c");
    assert_eq!(
        actions[2].status,
        sagashield::ActionStatus::Failed,
        "ToolC deve essere FAILED (execute fallita)"
    );

    Ok(())
}

#[tokio::test]
async fn rollback_marks_failed_when_compensation_fails() -> Result<(), KernelError> {
    let wal = Wal::open_in_memory()?;
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    wal.create_session(&session_id)?;

    let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // ToolB compensa con fallimento.
    let tool_a: Arc<dyn TransactionalTool> =
        Arc::new(MockTool::new("tool_a", false, false, Arc::clone(&order)));
    let tool_b: Arc<dyn TransactionalTool> =
        Arc::new(MockTool::new("tool_b", false, true, Arc::clone(&order)));

    let mut registry: HashMap<String, Arc<dyn TransactionalTool>> = HashMap::new();
    registry.insert("tool_a".to_owned(), Arc::clone(&tool_a));
    registry.insert("tool_b".to_owned(), Arc::clone(&tool_b));

    run_step(&wal, &tool_a, &session_id, 0, json!({})).await?;
    run_step(&wal, &tool_b, &session_id, 1, json!({})).await?;

    let res = wal.rollback(&session_id, &registry).await;
    assert!(
        matches!(res, Err(KernelError::RollbackPartial { failed: 1, .. })),
        "atteso RollbackPartial con 1 fallimento, ottenuto {res:?}"
    );

    let actions = wal.get_actions(&session_id)?;
    // LIFO: B tentato per primo e fallito → FAILED; A comunque compensato.
    assert_eq!(actions[0].status, sagashield::ActionStatus::Compensated);
    assert_eq!(actions[1].status, sagashield::ActionStatus::Failed);

    Ok(())
}
