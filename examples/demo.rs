//! Demo spettacolare Fase 3: rollback su effetti reali.
//!
//! Esegui con: `cargo run --example demo`
//!
//! 1. Avvio sessione.
//! 2. Step 1: scrittura file reale.
//! 3. Step 2: pagamento fittizio.
//! 4. Step 3: crash intenzionale.
//! 5. Kernel: "CRASH RILEVATO -> Avvio Rollback LIFO...".
//! 6. Verifica: file eliminato, pagamento stornato, sistema in sicurezza.

use std::sync::Arc;

use sagashield::tools::{CrashTool, FsWriteTool, MockPaymentTool};
use sagashield::{AgentKernel, ToolRegistry, TransactionalTool, Wal};
use serde_json::json;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_ansi(true)
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();

    println!("================================================================");
    println!("  sagashield — DEMO: FSM + WAL + Rollback su effetti reali");
    println!("================================================================");

    // Setup kernel.
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    let pay_tool = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay_tool.clone();
    registry.register(Arc::new(FsWriteTool::new()))?;
    registry.register(pay_dyn)?;
    registry.register(Arc::new(CrashTool))?;
    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);

    // 1. Avvio sessione.
    let session = uuid::Uuid::new_v4();
    info!("(1/6) Avvio sessione {}", session);
    info!("      FSM iniziale: {}", kernel.state());
    kernel.begin_planning()?;
    info!("      FSM -> Planning");

    let path = "./agent_demo_output.txt".to_owned();
    let _ = std::fs::remove_file(&path);

    // 2. Step 1: scrittura file reale.
    kernel.begin_tool("fs.write")?;
    info!("(2/6) Step 1: FsWriteTool scrive il file reale '{path}' ...");
    kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": path, "content": "dati critici della saga" }),
            None,
        )
        .await?;
    info!(
        "      File su disco? {}",
        std::path::Path::new(&path).exists()
    );
    info!("      FSM -> {}", kernel.state());

    // 3. Step 2: pagamento fittizio.
    kernel.begin_tool("mock.pay")?;
    info!("(3/6) Step 2: MockPaymentTool addebita 'pay-demo-1' (250 EUR) ...");
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-demo-1", "amount": 250 }),
            None,
        )
        .await?;
    info!(
        "      Ledger: pay-demo-1 = {:?}",
        pay_tool.status("pay-demo-1")
    );
    info!("      FSM -> {}", kernel.state());

    // 4. Step 3: crash intenzionale.
    kernel.begin_tool("crash.tool")?;
    warn!("(4/6) Step 3: CrashTool va in CRASH intenzionale ...");
    match kernel
        .execute_tool(&session, "crash.tool", json!({}), None)
        .await
    {
        Ok(_) => error!("      ATTESO un crash, ma il tool ha avuto successo!"),
        Err(e) => {
            // 5. Intervento del kernel (loggato anche dentro execute_tool).
            error!("(5/6) CRASH RILEVATO -> Avvio Rollback LIFO...: {e}");
        }
    }

    // 6. Verifica finale.
    let file_gone = !std::path::Path::new(&path).exists();
    let refunded = pay_tool.status("pay-demo-1") == Some("REFUNDED".to_owned());
    let fsm_failed = kernel.state().to_string() == "Failed";
    info!("(6/6) Verifica post-rollback:");
    info!(
        "      - File eliminato?        {file_gone} (esiste: {})",
        std::path::Path::new(&path).exists()
    );
    info!(
        "      - Pagamento stornato?    {refunded} ({:?})",
        pay_tool.status("pay-demo-1")
    );
    info!(
        "      - FSM in Failed?         {fsm_failed} ({})",
        kernel.state()
    );

    let actions = wal.get_actions(&session.to_string())?;
    for a in &actions {
        info!(
            "      WAL seq={} tool={} status={}",
            a.step_seq, a.tool_id, a.status
        );
    }

    if file_gone && refunded && fsm_failed {
        println!("----------------------------------------------------------------");
        println!("  File eliminato, pagamento stornato, sistema in sicurezza. OK.");
        println!("----------------------------------------------------------------");
    } else {
        println!("----------------------------------------------------------------");
        println!("  VERIFICA FALLITA: rollback incompleto!");
        println!("----------------------------------------------------------------");
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}
