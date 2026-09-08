//! OTel audit export demo: mini-saga in-memory → `resourceSpans` su stdout.
//!
//! Esegui con: `cargo run --example otel_export`
//!
//! Nessun file scritto, nessun side-effect residuo: il WAL è in-memory e i
//! tool usati sono simulati (pagamenti) + crash deterministico.

use std::sync::Arc;

use sagashield::tools::{CrashTool, MockPaymentTool};
use sagashield::{AgentKernel, AuditExporter, ToolRegistry, Wal};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // WAL in-memory: zero file, zero residui.
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(MockPaymentTool::new()))?;
    registry.register(Arc::new(CrashTool))?;

    let mut kernel = AgentKernel::new(wal, registry);
    let session = uuid::Uuid::new_v4();

    // Mini-saga: 2 OK + 1 crash (rollback LIFO automatico).
    kernel.begin_planning()?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "otel-1" }),
            None,
        )
        .await?;
    kernel.begin_tool("mock.pay")?;
    kernel
        .execute_tool(
            &session,
            "mock.pay",
            json!({ "payment_id": "otel-2" }),
            None,
        )
        .await?;
    kernel.begin_tool("crash.tool")?;
    let _ = kernel
        .execute_tool(&session, "crash.tool", json!({}), None)
        .await;

    // Export audit OTel e asserzione su spans.len() >= 3.
    let doc = AuditExporter::export_session_otel_json(kernel.wal(), &session)?;
    let parsed: Value = serde_json::from_str(&doc)?;
    let spans = parsed["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .ok_or("missing spans in OTel document")?;
    assert!(spans.len() >= 3, "expected >= 3 spans, got {}", spans.len());

    // Documento OTel su stdout (pronto per Datadog / Honeycomb / Jaeger).
    println!("{doc}");
    Ok(())
}
