//! L4 Memory Vault: scope isolation, dedup, promozione, decay, tool kernel.

use std::sync::Arc;

use sagashield::{
    AgentKernel, MemoryRecallTool, MemoryScope, MemoryStoreTool, MemoryVault, NewMemoryInput,
    RecallPolicy, ToolRegistry, Wal,
};
use serde_json::json;

fn fact(scope: MemoryScope, content: &str, importance: i64) -> NewMemoryInput {
    NewMemoryInput {
        scope,
        kind: sagashield::MemoryKind::Fact,
        content: content.to_owned(),
        importance: Some(importance),
    }
}

#[test]
fn store_and_recall_scoped() -> Result<(), Box<dyn std::error::Error>> {
    let vault = MemoryVault::open_in_memory()?;
    let ada = MemoryScope::new("acme", "support", "ada");
    let bob = MemoryScope::new("acme", "support", "bob");

    vault.store(fact(ada.clone(), "project Alpha uses region EU", 80))?;
    let hits = vault.recall(&ada, "which region project Alpha", &RecallPolicy::default())?;
    assert_eq!(hits.len(), 1);
    assert!(hits[0].content.contains("region EU"));

    // Isolamento: Bob non vede i ricordi di Ada.
    let other = vault.recall(&bob, "which region project Alpha", &RecallPolicy::default())?;
    assert!(other.is_empty());
    Ok(())
}

#[test]
fn store_is_idempotent_and_promotes_on_recall() -> Result<(), Box<dyn std::error::Error>> {
    let vault = MemoryVault::open_in_memory()?;
    let scope = MemoryScope::new("acme", "support", "ada");
    let (id1, deduped1) = vault.store(fact(scope.clone(), "weekly summaries on monday", 60))?;
    assert!(!deduped1);
    let (id2, deduped2) = vault.store(fact(scope.clone(), "weekly summaries on monday", 60))?;
    assert!(deduped2);
    assert_eq!(id1, id2);

    let before = vault.get(&id1)?.expect("exists").access_count;
    let _ = vault.recall(&scope, "weekly summaries monday", &RecallPolicy::default())?;
    let after = vault.get(&id1)?.expect("exists").access_count;
    assert_eq!(after, before + 1);
    Ok(())
}

#[test]
fn prune_weak_removes_noise_only() -> Result<(), Box<dyn std::error::Error>> {
    let vault = MemoryVault::open_in_memory()?;
    let now = sagashield::knowledge::now_secs()?;
    let scope = MemoryScope::new("acme", "support", "ada");
    let (weak_id, _) = vault.store(fact(scope.clone(), "debug log noise xyz", 5))?;
    let (strong_id, _) = vault.store(fact(
        scope.clone(),
        "production api key rotation policy",
        90,
    ))?;
    // Il forte viene riusato -> protetto dal prune.
    let _ = vault.recall(&scope, "api key rotation policy", &RecallPolicy::default())?;

    let pruned = vault.prune_weak(20, -1, now)?;
    assert_eq!(pruned, 1);
    assert!(vault.get(&weak_id)?.is_none());
    assert!(vault.get(&strong_id)?.is_some());
    Ok(())
}

#[tokio::test]
async fn memory_tools_integrate_with_kernel() -> Result<(), Box<dyn std::error::Error>> {
    let vault = Arc::new(MemoryVault::open_in_memory()?);
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(MemoryStoreTool::new(Arc::clone(&vault))))?;
    registry.register(Arc::new(MemoryRecallTool::new(Arc::clone(&vault))))?;
    let mut kernel = AgentKernel::new(wal, registry);

    let session = uuid::Uuid::new_v4();
    kernel.begin_planning()?;
    kernel.begin_tool("memory.store")?;
    let stored = kernel
        .execute_tool(
            &session,
            "memory.store",
            json!({
                "tenant": "acme", "agent": "support", "user_id": "ada",
                "kind": "preference", "content": "user prefers weekly summaries on monday",
                "importance": 70
            }),
            None,
        )
        .await?;
    assert_eq!(stored.data["deduped"], false);

    kernel.begin_tool("memory.recall")?;
    let recalled = kernel
        .execute_tool(
            &session,
            "memory.recall",
            json!({
                "tenant": "acme", "agent": "support", "user_id": "ada",
                "query": "weekly summaries monday"
            }),
            None,
        )
        .await?;
    assert_eq!(recalled.data["count"], 1);
    Ok(())
}
