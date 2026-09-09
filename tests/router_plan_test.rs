//! L0 Router: VRAM-fit, context-fit, SLO costo/latenza/energia.

use std::sync::Arc;

use sagashield::{
    AgentKernel, BackendCatalog, InferenceRouter, RouterPlanTool, SloPolicy, TaskSpec,
    ToolRegistry, Wal,
};
use serde_json::json;

fn task(ctx: u64, out: u64) -> TaskSpec {
    TaskSpec {
        context_tokens: ctx,
        expected_output_tokens: out,
        min_quality: 0,
    }
}

#[test]
fn prefers_local_when_vram_fits() -> Result<(), Box<dyn std::error::Error>> {
    let router = InferenceRouter::new(BackendCatalog::consumer_presets(16.0));
    let plan = router.plan(&task(4_000, 512), &SloPolicy::default())?;
    assert!(plan.is_local);
    assert!(plan.est_vram_gb <= 16.0);
    assert_eq!(plan.est_cost_usd, 0.0);
    Ok(())
}

#[test]
fn bursts_to_cloud_when_context_exceeds_local() -> Result<(), Box<dyn std::error::Error>> {
    let router = InferenceRouter::new(BackendCatalog::consumer_presets(16.0));
    // 100k supera tutti i context_max locali (max 32k) -> cloud.
    let plan = router.plan(&task(100_000, 512), &SloPolicy::default())?;
    assert!(!plan.is_local);
    Ok(())
}

#[test]
fn no_feasible_backend_errors_loudly() -> Result<(), Box<dyn std::error::Error>> {
    let router = InferenceRouter::new(BackendCatalog::consumer_presets(16.0));
    let slo = SloPolicy {
        max_wh_per_task: Some(0.000_001),
        ..Default::default()
    };
    let err = router
        .plan(&task(4_000, 4_000), &slo)
        .expect_err("must refuse, not silently degrade");
    assert!(err.to_string().contains("NO_FEASIBLE_BACKEND"));
    Ok(())
}

#[tokio::test]
async fn router_tool_integrates_with_kernel() -> Result<(), Box<dyn std::error::Error>> {
    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    registry.register(Arc::new(RouterPlanTool::consumer(16.0)))?;
    let mut kernel = AgentKernel::new(wal, registry);

    let session = uuid::Uuid::new_v4();
    kernel.begin_planning()?;
    kernel.begin_tool("router.plan")?;
    let out = kernel
        .execute_tool(
            &session,
            "router.plan",
            json!({"context_tokens": 4000, "expected_output_tokens": 512, "vram_gb": 16.0}),
            None,
        )
        .await?;
    assert!(out.data.get("backend").is_some());
    assert!(out.data.get("est_cost_usd").is_some());
    Ok(())
}
