//! Demo L4 Memory Vault: memoria scopata e portabile dentro una saga.
//!
//! ```sh
//! cargo run --example memory_demo
//! ```

use std::sync::Arc;

use sagashield::{
    AgentKernel, MemoryRecallTool, MemoryScope, MemoryStoreTool, MemoryVault, NewMemoryInput,
    RecallPolicy, ToolRegistry, Wal,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault = Arc::new(MemoryVault::open_in_memory()?);
    let ada = MemoryScope::new("acme", "support", "ada");
    vault.store(NewMemoryInput {
        scope: ada.clone(),
        kind: sagashield::MemoryKind::Preference,
        content: "user prefers weekly summaries on monday".to_owned(),
        importance: Some(70),
    })?;
    vault.store(NewMemoryInput {
        scope: ada.clone(),
        kind: sagashield::MemoryKind::Fact,
        content: "project Alpha uses region EU".to_owned(),
        importance: Some(80),
    })?;

    let hits = vault.recall(&ada, "weekly summaries monday", &RecallPolicy::default())?;
    println!("recall hits: {}", hits.len());
    for h in &hits {
        println!("  - score={} :: {}", h.score, h.content);
    }

    // Stesso vault via tool transazionali: la memoria sopravvive al cambio modello.
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(MemoryStoreTool::new(Arc::clone(&vault))))?;
    registry.register(Arc::new(MemoryRecallTool::new(Arc::clone(&vault))))?;
    let mut kernel = AgentKernel::new(wal, registry);
    let session = uuid::Uuid::new_v4();
    kernel.begin_planning()?;
    kernel.begin_tool("memory.recall")?;
    let out = kernel
        .execute_tool(
            &session,
            "memory.recall",
            json!({"tenant": "acme", "agent": "support", "user_id": "ada",
                   "query": "region project Alpha"}),
            None,
        )
        .await?;
    println!("kernel recall count: {}", out.data["count"]);
    Ok(())
}
