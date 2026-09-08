---
name: Bug report
about: Something behaves differently than specified
title: "fix: "
labels: bug
---

## Expected behavior

What should happen, per docs / `SPEC.md` / `BENCHMARK.md`?

## Observed behavior

What happens instead? Paste the exact error, WAL rows, or eval numbers.

## Minimal reproduction

```rust
// or: minimal MCP transcript / python snippet / eval scenario
```

Steps: commands run, seed used, config (features, OS).

## Environment

- SagaShield version (`Cargo.toml` / `pip show sagashield`):
- OS:
- Rust (`rustc --version`) / Python (`python --version`):

## Security relevance

Does this touch `src/security/`, Step-0, rollback, or the WAL?
If it may be a vulnerability, use **Security → Report a vulnerability**
(private advisory) instead — see `SECURITY.md`.
