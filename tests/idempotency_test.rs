//! TEST — Idempotency Key Engine (anti-retry).
//!
//! `MockPaymentTool` (250€) con chiave `idem-key-123` → OK, un addebito.
//! Richiamo con la stessa chiave → OK cachato, ledger ancora a UN addebito.

use std::sync::Arc;

use sagashield::tools::MockPaymentTool;
use sagashield::{ActionStatus, AgentKernel, KernelError, ToolRegistry, TransactionalTool, Wal};
use serde_json::json;

#[tokio::test]
async fn retry_with_same_key_returns_cached_output() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    let pay_tool = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay_tool.clone();
    registry.register(pay_dyn)?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();
    let session_str = session.to_string();
    let args = json!({ "payment_id": "pay-idem-1", "amount": 250 });

    // Prima esecuzione: addebito reale.
    kernel.begin_planning()?;
    kernel.begin_tool("mock.pay")?;
    let first = kernel
        .execute_tool(
            &session,
            "mock.pay",
            args.clone(),
            Some("idem-key-123".to_owned()),
        )
        .await?;
    assert_eq!(pay_tool.ledger_size(), 1);
    assert_eq!(pay_tool.status("pay-idem-1"), Some("CHARGED".to_owned()));

    // Retry di rete con la stessa chiave: output cachato, nessun nuovo addebito.
    kernel.begin_tool("mock.pay")?;
    let second = kernel
        .execute_tool(
            &session,
            "mock.pay",
            args.clone(),
            Some("idem-key-123".to_owned()),
        )
        .await?;
    assert_eq!(second, first, "il retry deve ritornare l'output cachato");
    assert_eq!(
        pay_tool.ledger_size(),
        1,
        "esattamente UN addebito nel ledger"
    );

    // WAL: una sola riga COMMITTED (nessuna duplicazione).
    let actions = wal.get_actions(&session_str)?;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].status, ActionStatus::Committed);
    assert_eq!(actions[0].idempotency_key, "idem-key-123");

    Ok(())
}

#[tokio::test]
async fn different_keys_execute_independently() -> Result<(), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    let pay_tool = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay_tool.clone();
    registry.register(pay_dyn)?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();

    kernel.begin_planning()?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-a" }),
            Some("key-a".to_owned()),
        )
        .await?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-b" }),
            Some("key-b".to_owned()),
        )
        .await?;

    assert_eq!(
        pay_tool.ledger_size(),
        2,
        "due chiavi diverse, due addebiti"
    );
    assert_eq!(wal.get_actions(&session.to_string())?.len(), 2);

    Ok(())
}
