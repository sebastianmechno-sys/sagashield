//! TEST v0.3 — DLQ con cascading rollback, human-in-the-loop, pruning.
//!
//! - DLQ: compensate fallita → ciclo LIFO continua, orfana in DLQ UNRESOLVED.
//! - HIL: tool irreversibile → AwaitingApproval; reject compensa il passato,
//!   approve con token esegue con successo.
//! - Pruning: sessioni terminali vecchie eliminate, DLQ UNRESOLVED conservata.

use std::sync::Arc;
use std::time::Duration;

use sagashield::tools::{FsWriteTool, MockPaymentTool};
use sagashield::{
    ActionStatus, AgentKernel, AgentState, KernelError, ToolContext, ToolOutput, ToolRegistry,
    TransactionalTool, Wal,
};
use serde_json::{Value, json};

/// Tool la cui compensazione fallisce intenzionalmente (per la DLQ).
struct FailCompensateTool;

#[async_trait::async_trait]
impl TransactionalTool for FailCompensateTool {
    fn id(&self) -> &'static str {
        "fail.comp"
    }

    async fn execute(&self, ctx: &ToolContext, _args: Value) -> Result<ToolOutput, KernelError> {
        Ok(ToolOutput::new(json!({ "seq": ctx.step_seq })))
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        Err(KernelError::CompensationFailed {
            tool_id: self.id().to_owned(),
            message: "intentional compensation failure".to_owned(),
        })
    }
}

/// Tool irreversibile (2-Phase Commit).
struct SealVaultTool;

#[async_trait::async_trait]
impl TransactionalTool for SealVaultTool {
    fn id(&self) -> &'static str {
        "seal.vault"
    }

    fn is_irreversible(&self) -> bool {
        true
    }

    async fn execute(&self, _ctx: &ToolContext, _args: Value) -> Result<ToolOutput, KernelError> {
        Ok(ToolOutput::new(json!({ "sealed": true })))
    }

    async fn compensate(
        &self,
        _ctx: &ToolContext,
        _args: Value,
        _output: ToolOutput,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

fn temp_file(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("ak_dlq_{name}_{}.txt", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

#[tokio::test]
async fn failed_compensation_lands_in_dlq_and_rollback_cascades() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(FsWriteTool::new()))?;
    registry.register(Arc::new(FailCompensateTool))?;
    registry.register(Arc::new(sagashield::tools::CrashTool))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();
    let path = temp_file("cascade");
    let _ = std::fs::remove_file(&path);

    // Step 0: file reale. Step 1: compensate che fallirà. Step 2: crash.
    kernel.begin_planning()?;
    kernel.begin_tool("fs.write")?;
    kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": path, "content": "x" }),
            None,
        )
        .await?;
    kernel.begin_tool("fail.comp")?;
    kernel
        .execute_tool(&session, "fail.comp", json!({}), None)
        .await?;
    kernel.begin_tool("crash.tool")?;
    let err = kernel
        .execute_tool(&session, "crash.tool", json!({}), None)
        .await
        .expect_err("crash atteso");
    assert!(
        matches!(err, KernelError::ToolExecution { .. }),
        "report di rollback parziale atteso, ottenuto: {err}"
    );

    // Cascata: lo step 0 è stato comunque compensato (file sparito).
    assert!(
        !std::path::Path::new(&path).exists(),
        "il file deve essere FISICAMENTE cancellato"
    );
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions[0].status, ActionStatus::Compensated);
    assert_eq!(actions[1].status, ActionStatus::Failed);
    assert_eq!(actions[2].status, ActionStatus::Failed);

    // Lo step 1 è in DLQ come UNRESOLVED + sessione marcata.
    let dlq = wal.get_unresolved_dlq()?;
    assert_eq!(dlq.len(), 1);
    assert_eq!(dlq[0].tool_name, "fail.comp");
    assert_eq!(dlq[0].status, "UNRESOLVED");
    assert_eq!(dlq[0].session_id, session_str);
    assert_eq!(
        wal.session_status(&session_str)?,
        Some("RECOVERED_WITH_DLQ".to_owned())
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn irreversible_tool_waits_and_rejects_with_rollback() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(FsWriteTool::new()))?;
    registry.register(Arc::new(SealVaultTool))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();
    let path = temp_file("hil");
    let _ = std::fs::remove_file(&path);

    kernel.begin_planning()?;
    kernel.begin_tool("fs.write")?;
    kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": path, "content": "y" }),
            None,
        )
        .await?;

    // L'esecuzione si parcheggia in AwaitingApproval con token.
    kernel.begin_tool("seal.vault")?;
    let err = kernel
        .execute_tool(&session, "seal.vault", json!({}), None)
        .await
        .expect_err("serve approvazione");
    let token = match err {
        KernelError::ApprovalRequired { tool_name, token } => {
            assert_eq!(tool_name, "seal.vault");
            assert!(!token.is_empty());
            token
        }
        other => panic!("atteso ApprovalRequired, ottenuto: {other}"),
    };
    assert_eq!(
        kernel.state(),
        &AgentState::AwaitingApproval {
            tool_name: "seal.vault".to_owned(),
            approval_token: token.clone(),
        }
    );
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions[1].status, ActionStatus::PendingApproval);

    // Rifiuto: FAILED + rollback del passato (file sparito).
    kernel.reject_action(&session, &token, "too risky").await?;
    assert_eq!(kernel.state(), &AgentState::Failed);
    assert!(
        !std::path::Path::new(&path).exists(),
        "il rollback post-rifiuto deve cancellare il file"
    );
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions[0].status, ActionStatus::Compensated);
    assert_eq!(actions[1].status, ActionStatus::Failed);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn irreversible_tool_approves_and_commits() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(SealVaultTool))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();

    kernel.begin_planning()?;
    kernel.begin_tool("seal.vault")?;
    let err = kernel
        .execute_tool(&session, "seal.vault", json!({}), None)
        .await
        .expect_err("serve approvazione");
    let token = match err {
        KernelError::ApprovalRequired { token, .. } => token,
        other => panic!("atteso ApprovalRequired, ottenuto: {other}"),
    };

    // Token errato: nessun effetto.
    let bad = kernel
        .approve_action(&session, "wrong-token")
        .await
        .expect_err("token errato deve fallire");
    assert!(matches!(bad, KernelError::InvalidStateTransition { .. }));

    // Token giusto: esecuzione completata.
    let out = kernel.approve_action(&session, &token).await?;
    assert_eq!(out.data["sealed"], true);
    assert_eq!(kernel.state(), &AgentState::Verifying);
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].status, ActionStatus::Committed);

    Ok(())
}

#[tokio::test]
async fn pruning_deletes_old_terminals_but_keeps_dlq() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    let pay = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay.clone();
    registry.register(pay_dyn)?;

    // Sessione A: COMMITTED → recovery → RECOVERED (invecchierà).
    let session_a = uuid::Uuid::new_v4().to_string();
    let ctx_a = ToolContext::new(session_a.clone(), 0, "mock.pay");
    let args_a = json!({ "payment_id": "pay-prune-a" });
    let id_a = wal.log_action(&ctx_a, &args_a)?;
    wal.mark_committed(
        id_a,
        &sagashield::ToolOutput::new(json!({ "payment_id": "pay-prune-a" })),
    )?;
    let recovered = wal.recover_dangling(&registry.snapshot()?).await?;
    assert_eq!(recovered, vec![session_a.clone()]);

    // Invecchia A oltre la granularità secondi di SQLite.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Sessione B: fresca, ACTIVE + COMMITTED, con DLQ UNRESOLVED.
    let session_b = uuid::Uuid::new_v4().to_string();
    let ctx_b = ToolContext::new(session_b.clone(), 0, "mock.pay");
    let id_b = wal.log_action(&ctx_b, &json!({ "payment_id": "pay-prune-b" }))?;
    wal.mark_committed(
        id_b,
        &sagashield::ToolOutput::new(json!({ "payment_id": "pay-prune-b" })),
    )?;
    let action_b = wal.get_actions(&session_b)?[0].clone();
    wal.record_dlq(&session_b, &action_b, "manual SRE entry")?;

    let report = wal.prune_history(0)?;
    assert_eq!(report.sessions_deleted, 1, "solo la sessione vecchia");
    assert_eq!(report.actions_deleted, 1);
    assert!(wal.get_actions(&session_a)?.is_empty());
    assert_eq!(wal.get_actions(&session_b)?.len(), 1);
    assert_eq!(wal.session_status(&session_b)?, Some("ACTIVE".to_owned()));

    // DLQ UNRESOLVED mai toccata + vacuum OK.
    assert_eq!(wal.get_unresolved_dlq()?.len(), 1);
    wal.vacuum()?;

    Ok(())
}
