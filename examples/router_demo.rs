//! Demo L0 Router: piano locale vs burst cloud con ledger energia/costo.
//!
//! ```sh
//! cargo run --example router_demo
//! ```

use sagashield::{BackendCatalog, InferenceRouter, SloPolicy, TaskSpec};

fn show(task: &TaskSpec, slo: &SloPolicy, vram: f64) {
    let router = InferenceRouter::new(BackendCatalog::consumer_presets(vram));
    match router.plan(task, slo) {
        Ok(p) => println!(
            "ctx={} -> {} (local={}) cost=${} latency={}ms wh={} [{}]",
            task.context_tokens,
            p.backend,
            p.is_local,
            p.est_cost_usd,
            p.est_latency_ms,
            p.est_wh,
            p.reason
        ),
        Err(e) => println!("ctx={} -> REFUSED: {e}", task.context_tokens),
    }
}

fn main() {
    let vram = 16.0;
    let slo = SloPolicy::default();
    for ctx in [4_000, 8_000, 32_000, 100_000] {
        show(
            &TaskSpec {
                context_tokens: ctx,
                expected_output_tokens: 512,
                min_quality: 0,
            },
            &slo,
            vram,
        );
    }
    // SLO energia stretta: rifiuta invece di degradare in silenzio.
    show(
        &TaskSpec {
            context_tokens: 4_000,
            expected_output_tokens: 4_000,
            min_quality: 0,
        },
        &SloPolicy {
            max_wh_per_task: Some(0.000_001),
            ..Default::default()
        },
        vram,
    );
}
