## Summary

What changes, and why (link issues: `Fixes #…`).

## Contributor checklist (mandatory)

- [ ] `cargo fmt` executed (`cargo fmt --check` clean)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] Unit/integration tests added or updated — no regressions (32+ tests green)
- [ ] `docs.rs` documentation updated (`///` on new public items)
- [ ] Zero `.unwrap()` introduced in `src/` (typed `KernelError` only)
- [ ] Security surface considered (`SECURITY.md` note if the threat model changes)
- [ ] `Cargo.toml` / `pyproject.toml` versions still in sync (if touched)
