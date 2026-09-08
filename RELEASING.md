# Releasing SagaShield

Strict [Semantic Versioning 2.0.0](https://semver.org/).

## Version policy (`0.x.y` pre-1.0)

- **Patch** (`0.x.y → 0.x.y+1`): bug fixes only, no API change.
- **Minor** (`0.x → 0.x+1`): backwards-compatible features
  (new tools, new MCP methods, new optional params).
- **Breaking changes** on `0.x` are allowed but must be declared
  explicitly: `feat!:` commit, dedicated CHANGELOG section, and migration
  notes. Anything removing/renaming a public item or changing wire
  behavior (WAL schema, MCP protocol, Python signatures) is breaking.

## Pre-release checklist

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test` green (32 integration tests + doctests, incl. fuzz corpus)
- [ ] `cargo doc --no-deps --all-features` warning-free
- [ ] `cargo run --example run_evals --release`: sagashield rows at
      0 residual corruption, 0 breaches, 0 duplicates
- [ ] Fuzzing sanity: `cargo test --test security_fuzz_test` green;
      for high-risk security changes, a `fuzz/run_fuzz` session
- [ ] **Version sync**: `Cargo.toml` == `pyproject.toml` (`0.1.0`)
- [ ] CHANGELOG updated (Added / Fixed / Security sections)
- [ ] `cargo package --allow-dirty` succeeds (dry-run for crates.io)
- [ ] Python wheel builds: `maturin build --features python`

## Publish order

1. Tag `v0.x.y`, push, wait for CI green on `main`.
2. `cargo publish` (Rust crate).
3. `maturin publish --features python` (PyPI wheel).
4. GitHub Release with the eval table and the audit notes.
