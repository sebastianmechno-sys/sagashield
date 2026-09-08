//! STRESS TEST 1 — Concorrenza massiccia: 50 saghe simultanee sullo stesso WAL.
//!
//! 25 task completano con successo (COMMITTED → Completed),
//! 25 task incontrano un crash e subiscono il rollback LIFO (→ Failed).
//! Atteso: zero deadlock, zero panic, DB coerente per ogni sessione.

use std::sync::Arc;
use std::time::Duration;

use sagashield::tools::CrashTool;
use sagashield::{
    ActionStatus, AgentKernel, AgentState, KernelError, ToolContext, ToolOutput, ToolRegistry,
    TransactionalTool, Wal,
};
use serde_json::{Value, json};

/// Tool OK velocissimo (nessun I/O reale, compensate no-op).
struct OkTool;

#[async_trait::async_trait]
impl TransactionalTool for OkTool {
    fn id(&self) -> &'static str {
        "ok.tool"
    }

    async fn execute(&self, ctx: &ToolContext, _args: Value) -> Result<ToolOutput, KernelError> {
        // Micro-yield per massimizzare l'interleaving tra i 50 task.
        tokio::task::yield_now().await;
        Ok(ToolOutput::new(json!({ "seq": ctx.step_seq })))
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

struct Report {
    session: String,
    success_path: bool,
    final_state: String,
}

/// Una saga completa: 2 step OK (+ complete) oppure 2 OK + crash (rollback).
async fn run_saga(wal: Arc<Wal>, success_path: bool) -> Report {
    let registry = ToolRegistry::new();
    registry.register(Arc::new(OkTool)).expect("register ok");
    registry
        .register(Arc::new(CrashTool))
        .expect("register crash");

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();

    kernel.begin_planning().expect("planning");
    kernel.begin_tool("ok.tool").expect("begin ok#1");
    kernel
        .execute_tool(&session, "ok.tool", json!({}), None)
        .await
        .expect("ok#1");
    kernel.begin_tool("ok.tool").expect("begin ok#2");
    kernel
        .execute_tool(&session, "ok.tool", json!({}), None)
        .await
        .expect("ok#2");

    if success_path {
        kernel.complete().expect("complete");
    } else {
        kernel.begin_tool("crash.tool").expect("begin crash");
        kernel
            .execute_tool(&session, "crash.tool", json!({}), None)
            .await
            .expect_err("crash must fail");
    }

    Report {
        session: session.to_string(),
        success_path,
        final_state: kernel.state().to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_concurrent_sagas_no_deadlock_no_panic() {
    let db = std::env::temp_dir().join(format!("ak_stress_{}.db", uuid::Uuid::new_v4()));
    let db_str = db.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&db);

    // Un unico WAL condiviso (una connessione + busy_timeout 5s + journal WAL).
    let wal = Arc::new(Wal::open(&db).expect("open wal"));

    let reports = tokio::time::timeout(Duration::from_secs(90), async {
        let mut handles = Vec::with_capacity(50);
        for i in 0..50 {
            let w = Arc::clone(&wal);
            let success_path = i % 2 == 0; // 25 OK, 25 crash (interleaved)
            handles.push(tokio::spawn(async move { run_saga(w, success_path).await }));
        }
        let mut reports = Vec::with_capacity(50);
        for h in handles {
            reports.push(h.await.expect("task panicked!"));
        }
        reports
    })
    .await
    .expect("TIMEOUT: probabile deadlock sotto concorrenza!");

    assert_eq!(reports.len(), 50);

    // FSM finali: 25 Completed, 25 Failed.
    let completed = reports
        .iter()
        .filter(|r| r.final_state == AgentState::Completed.to_string())
        .count();
    let failed = reports
        .iter()
        .filter(|r| r.final_state == AgentState::Failed.to_string())
        .count();
    assert_eq!(completed, 25, "attesi 25 Completed");
    assert_eq!(failed, 25, "attesi 25 Failed");

    // DB per-sessione: OK → [COMMITTED, COMMITTED]; crash → [COMPENSATED x2, FAILED].
    for r in &reports {
        let actions = wal.get_actions(&r.session).expect("read actions");
        if r.success_path {
            assert_eq!(actions.len(), 2, "sessione OK {}", r.session);
            assert!(actions.iter().all(|a| a.status == ActionStatus::Committed));
        } else {
            assert_eq!(actions.len(), 3, "sessione crash {}", r.session);
            assert_eq!(actions[0].status, ActionStatus::Compensated);
            assert_eq!(actions[1].status, ActionStatus::Compensated);
            assert_eq!(actions[2].status, ActionStatus::Failed);
            assert_eq!(actions[2].tool_id, "crash.tool");
        }
    }

    drop(wal);
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(format!("{db_str}-wal"));
    let _ = std::fs::remove_file(format!("{db_str}-shm"));
    let _ = std::fs::remove_file(format!("{db_str}-journal"));
}
