//! Demo L1 Knowledge Fabric: grounding governato dentro una saga.
//!
//! ```sh
//! cargo run --example knowledge_demo
//! ```
//!
//! Mostra: ingest con lineage+TTL, retrieve con citazioni,
//! rifiuto `INSUFFICIENT_GROUNDING` invece di allucinare,
//! quarantena dello stale.

use std::sync::Arc;

use sagashield::{
    AgentKernel, KnowledgeFabric, KnowledgeRetrieveTool, NewRecordInput, RetrievalPolicy,
    ToolRegistry, Wal,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let fabric = Arc::new(KnowledgeFabric::open_in_memory()?);
    fabric.ingest(NewRecordInput {
        source: "crm://policies/refund".to_owned(),
        owner: "support-ops".to_owned(),
        version: "v3".to_owned(),
        content: "Refunds are allowed within 30 days of purchase with receipt. Contact support with order id.".to_owned(),
        license: "internal".to_owned(),
        ttl_secs: Some(3_600),
    })?;
    // Record scaduto: TTL 60s ma aggiornato 2h fa.
    let now = sagashield::knowledge::now_secs()?;
    fabric.ingest_at(
        NewRecordInput {
            source: "crm://policies/old-shipping".to_owned(),
            owner: "support-ops".to_owned(),
            version: "v1".to_owned(),
            content: "Old shipping policy with outdated rates.".to_owned(),
            license: "internal".to_owned(),
            ttl_secs: Some(60),
        },
        now - 7_200,
        now - 7_200,
    )?;

    // 1. Retrieve diretto con citazioni.
    let hits = fabric.retrieve("refund 30 days receipt", &RetrievalPolicy::default())?;
    println!("grounded hits: {}", hits.len());
    for h in &hits {
        println!(
            "  - [{} {}] score={} :: {}",
            h.source, h.version, h.score, h.excerpt
        );
    }
    let citations = fabric.require_grounded("refund 30 days receipt", &hits, 1)?;
    println!("citations: {}", citations.len());

    // 2. Stale filtrato di default.
    let stale_hits = fabric.retrieve("old shipping rates", &RetrievalPolicy::default())?;
    println!("fresh hits for stale query: {}", stale_hits.len());
    match fabric.require_grounded("old shipping rates", &stale_hits, 1) {
        Ok(_) => println!("UNEXPECTED: stale passed fresh gate"),
        Err(e) => println!("correctly refused: {e}"),
    }
    println!("quarantined: {}", fabric.quarantine_expired(now)?);

    // 3. Stesso fabric come tool transazionale dentro il kernel.
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(KnowledgeRetrieveTool::new(Arc::clone(&fabric))))?;
    let mut kernel = AgentKernel::new(wal, registry);
    let session = uuid::Uuid::new_v4();
    kernel.begin_planning()?;
    kernel.begin_tool("knowledge.retrieve")?;
    let out = kernel
        .execute_tool(
            &session,
            "knowledge.retrieve",
            json!({ "query": "refund 30 days receipt" }),
            None,
        )
        .await?;
    println!("kernel tool grounded: {}", out.data["grounded"]);

    kernel.begin_tool("knowledge.retrieve")?;
    let err = kernel
        .execute_tool(
            &session,
            "knowledge.retrieve",
            json!({ "query": "hotel inesistente antartide xyz" }),
            None,
        )
        .await
        .expect_err("must refuse ungrounded");
    println!("kernel refused ungrounded as expected: {err}");
    Ok(())
}
