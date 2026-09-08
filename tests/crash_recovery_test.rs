//! STRESS TEST 2 — Crash recovery / blackout simulation.
//!
//! Fase A (processo "vivo"): fs.write OK + mock.pay OK + un PENDING orfano,
//! poi BLACKOUT (drop senza graceful shutdown, niente rollback).
//! Fase B (nuovo processo): `recover_dangling_sessions()` deve cancellare il
//! file orfano, stornare il pagamento e marcare la sessione RECOVERED.

use std::sync::Arc;

use sagashield::tools::{FsWriteTool, MockPaymentTool};
use sagashield::{
    ActionStatus, AgentKernel, KernelError, ToolContext, ToolRegistry, TransactionalTool, Wal,
};
use serde_json::json;

#[tokio::test]
async fn blackout_recovery_compensates_orphans() -> Result<(), KernelError> {
    let dir = std::env::temp_dir().join(format!("ak_blackout_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).map_err(|e| KernelError::ToolExecution {
        tool_id: "test".to_owned(),
        message: format!("mkdir failed: {e}"),
    })?;
    let db = dir.join("wal.db").to_string_lossy().to_string();
    let file = dir.join("orphan.txt").to_string_lossy().to_string();
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();

    // ---- Fase A: processo vivo, poi BLACKOUT ----
    {
        let wal = Arc::new(Wal::open(&db)?);
        let registry = ToolRegistry::new();
        registry.register(Arc::new(FsWriteTool::new()))?;
        registry.register(Arc::new(MockPaymentTool::new()))?;

        let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
        kernel.begin_planning()?;
        kernel.begin_tool("fs.write")?;
        kernel
            .execute_tool(
                &session,
                "fs.write",
                json!({ "path": file, "content": "orphan data" }),
                None,
            )
            .await?;
        kernel.begin_tool("mock.pay")?;
        kernel
            .execute_tool(
                &session,
                "mock.pay",
                json!({ "payment_id": "pay-orphan-1" }),
                None,
            )
            .await?;

        // Crash tra log ed execute del terzo step: riga PENDING orfana.
        let pending = ToolContext::new(session_str.clone(), 2, "mock.pay");
        wal.log_action(&pending, &json!({ "payment_id": "pay-orphan-2" }))?;

        assert!(std::path::Path::new(&file).exists(), "file pre-crash");
        // BLACKOUT: drop di kernel+wal senza rollback né complete.
    }

    // ---- Fase B: nuovo processo, istanze fresche (stesso file WAL) ----
    let wal2 = Arc::new(Wal::open(&db)?);
    let registry2 = ToolRegistry::new();
    let fresh_pay = Arc::new(MockPaymentTool::new());
    let fresh_dyn: Arc<dyn TransactionalTool> = fresh_pay.clone();
    registry2.register(Arc::new(FsWriteTool::new()))?;
    registry2.register(fresh_dyn)?;
    let kernel2 = AgentKernel::new(Arc::clone(&wal2), registry2);

    let recovered = kernel2
        .recover_dangling_sessions(kernel2.registry())
        .await?;
    assert_eq!(recovered, 1, "una sola sessione orfana");

    // Effetti orfani annullati fisicamente.
    assert!(
        !std::path::Path::new(&file).exists(),
        "il file orfano deve essere FISICAMENTE CANCELLATO"
    );
    assert_eq!(
        fresh_pay.status("pay-orphan-1"),
        Some("REFUNDED".to_owned()),
        "il pagamento orfano deve essere STORNATO"
    );

    // WAL: [COMPENSATED, COMPENSATED, FAILED] + sessione RECOVERED.
    let actions = wal2.get_actions(&session_str)?;
    assert_eq!(actions.len(), 3);
    assert_eq!(actions[0].status, ActionStatus::Compensated);
    assert_eq!(actions[1].status, ActionStatus::Compensated);
    assert_eq!(actions[2].status, ActionStatus::Failed);
    assert_eq!(
        wal2.session_status(&session_str)?,
        Some("RECOVERED".to_owned())
    );

    // Idempotenza: seconda recovery non trova nulla.
    let again = kernel2
        .recover_dangling_sessions(kernel2.registry())
        .await?;
    assert_eq!(again, 0);

    drop(wal2);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
