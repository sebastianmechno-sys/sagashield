//! Fuzz target: the path guard must never allow a sandbox escape.
//!
//! Invariant: if `check_path_access` returns `Ok(p)`, then `p` MUST start
//! with one of the `allowed_roots`. Any escape is an explicit panic.
//!
//! Run: `cargo +nightly fuzz run path_guard -- -max_total_time=300`

#![no_main]

use sagashield::{SecurityGuard, SecurityPolicy};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fn test_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/sandbox/workspace"),
        PathBuf::from("C:\\sandbox\\workspace"),
    ]
}

fn test_policy() -> SecurityPolicy {
    SecurityPolicy::new(
        test_roots(),
        vec![
            ".env".to_owned(),
            ".git".to_owned(),
            "id_rsa".to_owned(),
            "credentials".to_owned(),
        ],
        vec!["api.example.com".to_owned()],
    )
}

fuzz_target!(|data: &[u8]| {
    // Lossy interpretation: the guard must never panic, on any bytes.
    let s = String::from_utf8_lossy(data);
    let result = test_policy().check_path_access(std::path::Path::new(s.as_ref()));
    // Allow == containment, unconditionally. Escape == explicit panic.
    if let Ok(p) = result {
        let inside = test_roots().iter().any(|r| p.starts_with(r));
        assert!(inside, "SANDBOX ESCAPE: input {s:?} allowed as {p:?}");
    }
});
