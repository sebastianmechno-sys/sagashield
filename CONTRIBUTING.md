# Contributing to SagaShield

## Commit convention

[Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new user-facing capability (minor bump on `0.x`)
- `fix:` bug fix with regression test (patch bump)
- `perf:` measurable performance change (include before/after numbers)
- `docs:` docs, README, SPEC, comments only
- `chore:` tooling, CI, deps, refactors with no behavior change

Breaking changes: use `feat!:` / `fix!:` and call them out in the PR body;
they require a CHANGELOG entry and maintainer approval.

## Non-negotiable invariants

1. **Zero `.unwrap()` / zero `.expect()` in library code (`src/`).**
   Every failure is a typed `KernelError`. Tests and examples may use
   `expect` with a message, never bare `unwrap`.
2. **Every public type and method documents itself for `docs.rs`.**
   `///` comments must cover parameters, return values, and error cases.
   `cargo doc --no-deps` must stay warning-free.
3. **Every feature ships with regression tests.** New behavior without a
   failing-before/passing-after test is not merged. The suite
   (`cargo test`: 32 integration tests + doctests) must stay green.
4. **`cargo clippy --all-targets --all-features -- -D warnings` is clean.**
   No exceptions, no `#[allow]` without a linked issue explaining why.
5. **Security-sensitive changes** (anything under `src/security/`,
   `src/dispatcher.rs` Step-0, new tool surface) additionally require:
   - hostile-case tests (traversal, blocklist, spoofing variants),
   - a `SECURITY.md` impact note when the threat model changes.

## Workflow

```bash
cargo fmt --check          # or: cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test                 # 32 integration + doctests
cargo test --test security_fuzz_test   # hostile corpus
cargo run --example run_evals --release  # 0 residual corruption
```

Python bindings: `maturin develop --features python`, then
`python tests/python_binding_test.py`. Keep `Cargo.toml` and
`pyproject.toml` versions in sync (checked at release time).
