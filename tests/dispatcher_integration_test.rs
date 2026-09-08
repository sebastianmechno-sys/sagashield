//! Integrazione Fase 3: Dispatcher + FSM + WAL su effetti reali.
//!
//! Workflow: fs.write OK → mock.pay OK → crash.tool CRASH.
//! Atteso: errore corretto, FSM `Failed`, file FISICAMENTE eliminato,
//! pagamento stornato, WAL coerente.

use std::sync::Arc;

use sagashield::tools::{CrashTool, FsWriteTool, MockPaymentTool};
use sagashield::{
    ActionStatus, AgentKernel, AgentState, KernelError, ToolRegistry, TransactionalTool, Wal,
};
use serde_json::json;

fn temp_file(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("agent_kernel_{name}_{}.txt", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

#[tokio::test]
async fn dispatcher_rolls_back_real_side_effects() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();

    let pay_tool = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay_tool.clone();
    registry.register(Arc::new(FsWriteTool::new()))?;
    registry.register(pay_dyn)?;
    registry.register(Arc::new(CrashTool))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();

    let path = temp_file("rollback");
    let _ = std::fs::remove_file(&path);

    // Step 1: scrittura reale.
    kernel.begin_planning()?;
    kernel.begin_tool("fs.write")?;
    let out = kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": path, "content": "dati critici saga" }),
            None,
        )
        .await?;
    assert!(out.effects.iter().any(|e| e.contains(&path)));
    assert!(
        std::path::Path::new(&path).exists(),
        "il file deve esistere dopo execute"
    );

    // Step 2: pagamento fittizio.
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-it-1", "amount": 250 }),
            None,
        )
        .await?;
    assert_eq!(pay_tool.status("pay-it-1"), Some("CHARGED".to_owned()));

    // Step 3: crash intenzionale → rollback automatico.
    kernel.begin_tool("crash.tool")?;
    let err = kernel
        .execute_tool(&session, "crash.tool", json!({}), None)
        .await
        .expect_err("crash.tool deve fallire");
    assert!(
        matches!(&err, KernelError::ToolExecution { tool_id, .. } if tool_id == "crash.tool"),
        "errore atteso ToolExecution[crash.tool], ottenuto: {err}"
    );

    // Stato finale FSM.
    assert_eq!(kernel.state(), &AgentState::Failed);

    // Effetti fisici annullati.
    assert!(
        !std::path::Path::new(&path).exists(),
        "il file deve essere stato FISICAMENTE ELIMINATO dal rollback"
    );
    assert_eq!(pay_tool.status("pay-it-1"), Some("REFUNDED".to_owned()));

    // WAL coerente: A=COMPENSATED, B=COMPENSATED, C=FAILED.
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions.len(), 3);
    assert_eq!(actions[0].tool_id, "fs.write");
    assert_eq!(actions[0].status, ActionStatus::Compensated);
    assert_eq!(actions[1].tool_id, "mock.pay");
    assert_eq!(actions[1].status, ActionStatus::Compensated);
    assert_eq!(actions[2].tool_id, "crash.tool");
    assert_eq!(actions[2].status, ActionStatus::Failed);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn execute_without_authorization_fails_without_db_write() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(FsWriteTool::new()))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();

    // Nessun begin_planning/begin_tool → FSM Idle rifiuta senza toccare il DB.
    let err = kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": "x", "content": "y" }),
            None,
        )
        .await
        .expect_err("senza autorizzazione FSM deve fallire");
    assert!(
        matches!(&err, KernelError::InvalidStateTransition { .. }),
        "ottenuto: {err}"
    );
    assert_eq!(kernel.state(), &AgentState::Idle);
    assert!(wal.get_actions(&session.to_string())?.is_empty());

    Ok(())
}
