//! L1 Knowledge Fabric: freshness, lineage, citazioni, no-answer-from-memory.

use std::sync::Arc;

use sagashield::{
    AgentKernel, KnowledgeFabric, KnowledgeRetrieveTool, NewRecordInput, RetrievalPolicy,
    ToolRegistry, Wal,
};
use serde_json::json;

fn input(source: &str, content: &str, ttl_secs: Option<i64>) -> NewRecordInput {
    NewRecordInput {
        source: source.to_owned(),
        owner: "support-ops".to_owned(),
        version: "v1".to_owned(),
        content: content.to_owned(),
        license: "internal".to_owned(),
        ttl_secs,
    }
}

#[test]
fn retrieve_fresh_record_with_citation() -> Result<(), Box<dyn std::error::Error>> {
    let fabric = KnowledgeFabric::open_in_memory()?;
    fabric.ingest(input(
        "crm://policies/refund",
        "Refunds are allowed within 30 days of purchase with receipt.",
        Some(3_600),
    ))?;

    let hits = fabric.retrieve("refund policy 30 days", &RetrievalPolicy::default())?;
    assert_eq!(hits.len(), 1);
    assert!(!hits[0].stale);
    assert!(hits[0].excerpt.contains("30 days"));

    let citations = fabric.require_grounded("refund policy 30 days", &hits, 1)?;
    assert_eq!(citations.len(), 1);
    assert_eq!(citations[0].source, "crm://policies/refund");
    Ok(())
}

#[test]
fn stale_ttl_is_filtered_and_quarantined() -> Result<(), Box<dyn std::error::Error>> {
    let fabric = KnowledgeFabric::open_in_memory()?;
    // Record vecchio di 2 ore con TTL di 60s.
    let now = sagashield::knowledge::now_secs()?;
    let old = now - 7_200;
    let id = fabric.ingest_at(
        input(
            "crm://policies/old",
            "Old refund policy content here.",
            Some(60),
        ),
        old,
        old,
    )?;

    // require_fresh=true -> nessun hit -> InsufficientGrounding.
    let hits = fabric.retrieve("refund policy", &RetrievalPolicy::default())?;
    assert!(hits.is_empty());
    let err = fabric
        .require_grounded("refund policy", &hits, 1)
        .expect_err("must refuse memory fallback");
    assert!(matches!(
        err,
        sagashield::KernelError::InsufficientGrounding { .. }
    ));

    // Quarantena esplicita marca la riga.
    let n = fabric.quarantine_expired(now)?;
    assert_eq!(n, 1);
    let rec = fabric.get(&id)?.expect("record exists");
    assert!(rec.quarantined);

    // Con require_fresh=false lo stale passa ma marcato stale=true.
    let relaxed = RetrievalPolicy {
        require_fresh: false,
        ..Default::default()
    };
    let hits = fabric.retrieve_at("refund policy", &relaxed, now)?;
    assert_eq!(hits.len(), 1);
    assert!(hits[0].stale);
    Ok(())
}

#[test]
fn license_gate_blocks_unlicensed_sources() -> Result<(), Box<dyn std::error::Error>> {
    let fabric = KnowledgeFabric::open_in_memory()?;
    fabric.ingest(NewRecordInput {
        source: "youtube://video/123".to_owned(),
        owner: "creators".to_owned(),
        version: "v1".to_owned(),
        content: "Refund tutorial video transcript with policy details.".to_owned(),
        license: "youtube-tos".to_owned(),
        ttl_secs: None,
    })?;

    let gated = RetrievalPolicy {
        allowed_licenses: Some(vec!["internal".to_owned()]),
        ..Default::default()
    };
    let hits = fabric.retrieve("refund tutorial policy", &gated)?;
    assert!(hits.is_empty());
    Ok(())
}

#[tokio::test]
async fn retrieve_tool_integrates_with_kernel() -> Result<(), Box<dyn std::error::Error>> {
    let fabric = Arc::new(KnowledgeFabric::open_in_memory()?);
    fabric.ingest(input(
        "crm://policies/shipping",
        "Shipping refunds are issued only for lost parcels after 14 days.",
        None,
    ))?;

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
            json!({ "query": "shipping refunds lost parcels", "min_hits": 1 }),
            None,
        )
        .await?;
    assert_eq!(out.data["grounded"], true);
    assert_eq!(
        out.data["citations"][0]["source"],
        "crm://policies/shipping"
    );

    // Query senza grounding -> il tool fallisce con INSUFFICIENT_GROUNDING,
    // la saga compensa invece di allucinare.
    kernel.begin_tool("knowledge.retrieve")?;
    let err = kernel
        .execute_tool(
            &session,
            "knowledge.retrieve",
            json!({ "query": "antartide hotel inesistente xyz", "min_hits": 1 }),
            None,
        )
        .await
        .expect_err("must fail ungrounded");
    let msg = err.to_string();
    assert!(
        msg.contains("INSUFFICIENT_GROUNDING"),
        "unexpected error: {msg}"
    );
    Ok(())
}
