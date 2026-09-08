//! Fuzz target: the URL/domain parser must never panic and must never
//! admit a whitelist bypass.
//!
//! Invariant: if `check_network_access` returns `Ok`, the lowercased input
//! MUST contain a whitelisted domain (the parser only ever strips
//! scheme/authority/port decorations, it never invents hostnames).
//!
//! Run: `cargo +nightly fuzz run net_guard -- -max_total_time=300`

#![no_main]

use sagashield::{SecurityGuard, SecurityPolicy};
use libfuzzer_sys::fuzz_target;

const ALLOWED: [&str; 2] = ["api.example.com", "api.stripe.com"];

fn test_policy() -> SecurityPolicy {
    SecurityPolicy::new(
        vec![],
        vec![],
        ALLOWED.iter().map(|s| s.to_string()).collect(),
    )
}

fuzz_target!(|data: &[u8]| {
    // Only valid UTF-8 reaches the parser; invalid bytes are rejected
    // before parsing and must not panic either (covered by returning).
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let result = test_policy().check_network_access(s);
    if result.is_ok() {
        let lower = s.to_lowercase();
        let whitelisted = ALLOWED.iter().any(|a| lower.contains(a));
        assert!(whitelisted, "WHITELIST BYPASS: {s:?} admitted");
    }
});
