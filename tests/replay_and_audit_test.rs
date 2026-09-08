//! TEST — Deterministic replay + audit OTel.
//!
//! Saga: 2 tool OK + 1 crash → rollback LIFO.
//! `SessionReplay` verifica timeline/FSM/compensazioni (dry-run).
//! `AuditExporter` esporta OTel JSON con gli attributi richiesti.

use std::sync::Arc;

use sagashield::tools::{CrashTool, MockPaymentTool};
use sagashield::{AgentKernel, AuditExporter, KernelError, SessionReplay, ToolRegistry, Wal};
use serde_json::{Value, json};

/// Costruisce la saga crashata e ritorna (wal, sessione).
async fn crashed_saga() -> Result<(Arc<Wal>, uuid::Uuid), KernelError> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(MockPaymentTool::new()))?;
    registry.register(Arc::new(CrashTool))?;

    let mut kernel = AgentKernel::new(Arc::clone(&wal), registry);
    let session = uuid::Uuid::new_v4();

    kernel.begin_planning()?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-r1" }),
            None,
        )
        .await?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "pay-r2" }),
            None,
        )
        .await?;
    kernel.begin_tool("crash.tool")?;
    kernel
        .execute_tool(&session, "crash.tool", json!({}), None)
        .await
        .expect_err("crash atteso");

    Ok((wal, session))
}

#[tokio::test]
async fn replay_rebuilds_valid_timeline() -> Result<(), KernelError> {
    let (wal, session) = crashed_saga().await?;
    let timeline = SessionReplay::replay_session(&wal, &session)?;

    assert_eq!(timeline.session_id, session.to_string());
    assert_eq!(timeline.total_steps, 3);
    assert_eq!(timeline.compensations_executed, 2);
    assert_eq!(timeline.final_status, "Failed");
    assert!(timeline.duration_secs >= 0.0);

    // Timeline ordinata, stati coerenti con il WAL finale.
    let seqs: Vec<u64> = timeline
        .actions_timeline
        .iter()
        .map(|s| s.step_seq)
        .collect();
    assert_eq!(seqs, vec![0, 1, 2]);
    assert_eq!(timeline.actions_timeline[0].status, "COMPENSATED");
    assert_eq!(timeline.actions_timeline[1].status, "COMPENSATED");
    assert_eq!(timeline.actions_timeline[2].status, "FAILED");
    assert!(timeline.actions_timeline[0].compensated);
    assert!(!timeline.actions_timeline[2].compensated);

    // Ogni passo registra transizioni FSM formalmente valide.
    for step in &timeline.actions_timeline {
        assert!(
            !step.transitions.is_empty(),
            "step {} senza transizioni",
            step.step_seq
        );
        assert!(
            step.transitions
                .iter()
                .any(|t| t.starts_with("StartExecution")),
            "step {} senza StartExecution",
            step.step_seq
        );
    }

    Ok(())
}

#[tokio::test]
async fn audit_export_contains_otel_attributes() -> Result<(), KernelError> {
    let (wal, session) = crashed_saga().await?;
    let doc = AuditExporter::export_session_otel_json(&wal, &session)?;
    let v: Value = serde_json::from_str(&doc).expect("audit JSON valido");

    let spans = v["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .expect("spans array");
    assert_eq!(spans.len(), 3);

    // Ogni span porta sessione, tool e chiave di idempotenza.
    for span in spans {
        let attrs = span["attributes"].as_array().expect("attributes");
        let get = |key: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == key)
                .unwrap_or_else(|| panic!("attributo mancante: {key}"))
        };
        assert_eq!(
            get("agent.session_id")["value"]["stringValue"],
            session.to_string()
        );
        assert!(get("agent.tool.name")["value"]["stringValue"].is_string());
        assert!(get("agent.tool.idempotency_key")["value"]["stringValue"].is_string());
        assert!(get("agent.fsm.state")["value"]["stringValue"].is_string());
    }

    // Almeno uno span segnala il rollback (saga crashata).
    let any_rollback = spans.iter().any(|s| {
        s["attributes"]
            .as_array()
            .expect("attributes")
            .iter()
            .any(|a| a["key"] == "agent.rollback.triggered" && a["value"]["boolValue"] == true)
    });
    assert!(any_rollback, "agent.rollback.triggered = true atteso");

    // Catena parentale e tempi OTel presenti.
    assert!(spans[0].get("parentSpanId").is_none());
    assert!(spans[1]["parentSpanId"].is_string());
    for span in spans {
        assert!(span["traceId"].as_str().expect("traceId").len() == 32);
        assert!(
            span["startTimeUnixNano"]
                .as_str()
                .expect("start")
                .parse::<i64>()
                .expect("nanos")
                > 0
        );
    }

    Ok(())
}
