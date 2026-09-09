# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-09

### Added
- L1 Knowledge Fabric (`src/knowledge.rs`, tool `knowledge.retrieve`):
  lineage source/owner/version/license, TTL + quarantine, license gate,
  citations, `InsufficientGrounding` / `INSUFFICIENT_GROUNDING` no-memory-fallback.
- L4 Memory Vault (`src/memory.rs`, tools `memory.store` / `memory.recall`):
  scope `(tenant, agent, user_id)`, dedup idempotente, promozione accessi,
  `prune_weak` decay esplicito. Store compensabile via forget.
- L0 Inference Router (`src/router.rs`, tool `router.plan`):
  stima VRAM pesi + KV-cache, gate VRAM-fit / context-fit / SLO
  costo-latenza-Wh, preset consumer 16GB, `NO_FEASIBLE_BACKEND` esplicito.
- Test: 12 nuovi (4 knowledge + 4 memory + 4 router) + 5 unit; suite 53 verdi.
- Esempi: `knowledge_demo`, `memory_demo`, `router_demo`.

## [0.1.2] — 2026-09-08

### Fixed
- Release pipeline: Windows zip uses `Compress-Archive -Path` (wildcards
  don't expand under `-LiteralPath`); macOS checksum via `shasum -a 256`
  fallback; PyPI universal2 wheel via `--target universal2-apple-darwin`
  with both Apple toolchains.

## [0.1.1] — 2026-09-08

### Fixed
- CI on hosted runners: 8.3 short-name filter scoped to the final path
  component (CI temp dirs like `RUNNER~1` are legitimate); backslash
  rejected in names on every OS; explicit `[[bin]]` targets in
  `fuzz/Cargo.toml`; Python CI drives maturin inside a venv.

### Added
- Claude Code plugin marketplace manifest (`.claude-plugin/marketplace.json`,
  installable via `/plugin marketplace add`).
- `examples/otel_export.rs`: in-memory mini-saga (2 OK + 1 crash) printing
  the OpenTelemetry audit document to stdout.
- `fuzz-smoke` CI job: nightly `cargo-fuzz` build plus time-boxed smoke run
  of the `path_guard` / `net_guard` targets.

## [0.1.0] — 2026-09-08

### Added
- SQLite WAL Saga engine: `sessions`/`actions` tables, LIFO rollback,
  idempotency keys with `UNIQUE(session_id, idempotency_key)` index,
  `busy_timeout` + WAL mode, dangling-session crash recovery.
- FSM guardrail: deterministic `Idle → Planning → ExecutingTool →
  Verifying → Completed`, `Compensating → Failed`, default-deny with
  `InvalidStateTransition`.
- Tool dispatcher: `AgentKernel` unifying Step-0 security, FSM, WAL and
  automatic rollback; `ToolRegistry`, real `FsWriteTool` / `MockPaymentTool`
  / `CrashTool`.
- Step-0 security sandbox: lexical + symlink-aware path containment,
  blocklist, Windows reserved names, 8.3 short names, ADS blocking,
  trailing-dot/space normalization, domain whitelist with IP-literal
  rejection.
- MCP server (`sagashield-mcp`, JSON-RPC 2.0 over stdio): `initialize`,
  `tools/list`, `tools/call` (`fs_write`, `mock_pay`, `kernel_status`,
  `agent_kernel_exec` gateway, `kernel_replay_session`,
  `kernel_export_audit`).
- Deterministic session replay (`SessionReplay`) with formal FSM
  re-validation, and OpenTelemetry audit export (`AuditExporter`).
- Python bindings (`pip install sagashield`, maturin + PyO3 abi3):
  `SagaKernel`, `SecurityPolicy`, `@transactional_tool`,
  `SecurityViolationError`, LangChain adapter.
- Eval suite: 50 deterministic scenarios (seed=42) with raw JSON + CSV
  artifacts (`cargo run --example run_evals --release`).
- Coverage-guided fuzz targets (`fuzz/`: `path_guard`, `net_guard`) plus
  a 1.300+ hostile-input corpus in `security_fuzz_test`.
- Docs: `README.md`, `SPEC.md`, `SECURITY.md`, `BENCHMARK.md`,
  `CONTRIBUTING.md`, `RELEASING.md`, docs.rs API comments.

### Changed
- `FsWriteTool` creates missing parent directories (recursive write).
- Crate re-branded from `agent-kernel` to `sagashield`
  (binary `sagashield-mcp`, Python package `sagashield`).

### Security
- Documented application-level threat model and TOCTOU assumptions
  (`SECURITY.md`); responsible-disclosure procedure via private advisories.

### Fixed
- SQLite `CURRENT_TIMESTAMP` defaults (previously inverted `datetime` args
  returned `NULL` and violated `NOT NULL` constraints).
- `async fn` trait object-safety via `async-trait` for the tool registry.

[Unreleased]: https://github.com/sebastianmechno-sys/sagashield/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/sebastianmechno-sys/sagashield/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sebastianmechno-sys/sagashield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sebastianmechno-sys/sagashield/releases/tag/v0.1.0
