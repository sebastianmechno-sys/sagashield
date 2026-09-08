# SagaShield Evals — BASELINE vs SAGASHIELD (50 scenarios, seed=42)

Reproducible benchmark in the style of SWE-bench / Statewright evals:
one command, raw data, no hidden steps.

## Reproducibility Guide

Prerequisites: Rust 1.75+, a C compiler (for `rusqlite` bundled SQLite).

```bash
git clone https://github.com/sebastianmechno-sys/sagashield sagashield
cd sagashield
cargo run --example run_evals --release
```

What the command does:

1. Generates the 50-task suite deterministically (`evals/scenarios.rs`,
   xorshift64* with `EVAL_SEED = 42` — no `rand` dependency, same suite on
   every machine).
2. Runs every task twice in an isolated temp jail: once as a vanilla ReAct
   agent (direct `std::fs` + in-memory ledger, exceptions caught but never
   compensated), once through `AgentKernel` (Step-0 guard, FSM, SQLite WAL,
   LIFO rollback, idempotency engine).
3. Writes `evals/results/raw_eval_data.json` (per-task input, both outcomes,
   timestamps, nanosecond durations) and `evals/results/summary.csv`
   (per-category aggregates), and prints the ASCII table below.

## Threat & Failure Model

Formal definitions used for grading (see `examples/run_evals.rs`):

- **Success (goal met).**
  - *normal*: every step executed and every expected effect present.
  - *crash*: the injected failure is reported **and** zero residuals remain.
  - *adversarial*: the hostile write is rejected with nothing persisted
    outside policy (rejection *is* the goal).
  - *flaky*: the charge+write pair applied **exactly once** across the retry.
- **Residual Corruption (`residual`).** After a crash: any pre-crash file
  still on disk, or any pre-crash charge not `REFUNDED` in the ledger.
- **Security Breach (`breach`).** A hostile payload (traversal escaping the
  jail, `.env`/`credentials`/reserved-device/ADS name) accepted — i.e. not
  rejected — by the agent layer. Baseline never rejects by construction.
- **Duplicate (`dupl`).** Redundant side-effect applications beyond the first
  full pass (extra charges on retry).
- **Latency.** Wall time per tool step, p50/p99 in milliseconds. Includes
  SQLite I/O for SagaShield, raw syscalls for baseline.

## The Numbers

Measured with `cargo run --example run_evals --release` (Windows 11,
SQLite bundled, seed=42). Raw data: `evals/results/raw_eval_data.json`.

| category    | config     | tasks | succ | rate%  | residual | breach | dupl | p50ms | p99ms  |
|-------------|------------|------:|-----:|-------:|---------:|-------:|-----:|------:|-------:|
| normal      | baseline   |    15 |   15 |  100.0 |        0 |      0 |    0 | 0.359 |  0.628 |
| normal      | sagashield |    15 |   15 |  100.0 |        0 |      0 |    0 | 6.953 | 11.508 |
| crash       | baseline   |    15 |    0 |    0.0 |       15 |      0 |    0 | 0.002 |  0.655 |
| crash       | sagashield |    15 |   15 |  100.0 |        0 |      0 |    0 | 9.449 | 17.335 |
| adversarial | baseline   |    10 |    0 |    0.0 |        0 |     10 |    0 | 0.346 |  0.909 |
| adversarial | sagashield |    10 |   10 |  100.0 |        0 |      0 |    0 | 0.155 |  0.198 |
| flaky       | baseline   |    10 |    0 |    0.0 |        0 |      0 |   10 | 0.283 |  0.976 |
| flaky       | sagashield |    10 |   10 |  100.0 |        0 |      0 |    0 | 5.304 | 10.478 |
| TOTAL       | baseline   |    50 |   15 |   30.0 |       15 |     10 |   10 | 0.332 |  0.909 |
| TOTAL       | sagashield |    50 |   50 |  100.0 |        0 |      0 |    0 | 6.554 | 16.753 |

Reading: the vanilla agent scores 30% — perfect on the happy path, zero
everywhere else (15 dirty sagas, 10 accepted attacks, 10 double charges).
SagaShield scores 100% with zero residuals, zero breaches, zero duplicates.
Note the adversarial row: rejecting in 0.16 ms is *faster* than writing,
because Step-0 blocks before any I/O.

## Overhead Analysis

Honest cost accounting (release profile, per tool step):

- **SQLite WAL path** (`BEGIN`→`COMMITTED` + FSM transitions): p50 ≈ 6.6 ms
  total vs 0.33 ms baseline — roughly one fsync-dominated SQLite transaction
  per step on this machine. p99 ≈ 16.8 ms includes full LIFO rollbacks
  (compensating writes + deletes), i.e. the p99 *does useful recovery work*
  the baseline never performs.
- **Path screening** is sub-millisecond: adversarial rejections complete at
  p50 0.155 ms / p99 0.198 ms — lexical normalization plus a handful of
  substring checks, no syscalls on the hot path (canonicalization only
  touches the FS best-effort for existing paths).
- **Idempotent retries** skip execution entirely (WAL lookup + cached return),
  so the steady-state cost of a retry storm is one indexed `SELECT`, not a
  re-execution.

Limitations: single-node SQLite (no distributed consensus — see
“Best-Effort Guarantees” in `README.md`); latencies measured on one Windows
11 host, re-run on your hardware via the command above; the suite uses
synthetic tools (`fs.write`, `mock.pay`, `crash.tool`), not live LLM
planners, so planner-quality variance is out of scope by design.
