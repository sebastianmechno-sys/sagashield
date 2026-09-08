//! Deterministic synthetic benchmark scenarios (seed-fixed, no `rand` dep).
//!
//! 50 tasks in 4 categories: Normal Multi-Step (15), Crash & Midway
//! Failure (15), Adversarial Injections (10), Flaky Network Retries (10).
//! Included by `examples/run_evals.rs` via `#[path]`; same seed ⇒ same suite.

/// Fixed seed for 100% reproducibility (SWE-bench style).
pub const EVAL_SEED: u64 = 42;

/// Tiny xorshift64* PRNG (deterministic, dependency-free).
pub struct Rng(u64);

impl Rng {
    /// New generator from an explicit seed.
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform value in `0..n`.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}

/// Benchmark category (the goal each task is graded against).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// 2-4 legitimate steps; goal: all effects present.
    NormalMultiStep,
    /// 3-5 steps with a middle crash; goal: error reported, zero residuals.
    CrashMidway,
    /// One hostile write; goal: rejected, nothing escapes the jail.
    Adversarial,
    /// Same charge+write executed twice with one idempotency key;
    /// goal: effect applied exactly once.
    FlakyRetry,
}

impl Category {
    /// Stable short name for reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NormalMultiStep => "normal",
            Self::CrashMidway => "crash",
            Self::Adversarial => "adversarial",
            Self::FlakyRetry => "flaky",
        }
    }
}

/// One saga step (paths are scenario-dir relative unless adversarial).
#[derive(Debug, Clone)]
pub enum Step {
    /// Write `content` to `rel` (adversarial payloads escape on purpose).
    Write { rel: String, content: String },
    /// Simulated charge of `amount` cents on `id`.
    Charge { id: String, amount: u64 },
    /// Deterministic mid-saga crash (500 API / disk error / LLM bug).
    Crash { reason: &'static str },
}

/// One benchmark task.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Stable id, e.g. `normal-03`.
    pub id: String,
    /// Category (grading goal).
    pub category: Category,
    /// Ordered steps.
    pub steps: Vec<Step>,
    /// Anti-retry key (flaky category only).
    pub idem_key: Option<String>,
}

const CRASH_REASONS: [&str; 3] = ["500 API", "disk error", "LLM bug"];

/// Hostile payloads (one per adversarial task, cycled).
///
/// I traversal (`../`) sono calibrati per uscire dalla *jail* del guard
/// (la run-dir), non solo dalla sottocartella dello scenario: dalla
/// directory di scenario servono 3 livelli (`../../../`).
const ADVERSARIAL_PAYLOADS: [&str; 10] = [
    "../../../escape-00.txt",
    "..\\..\\..\\escape-01.txt",
    ".env",
    "credentials-03.json",
    "CON",
    "AUX.txt",
    "notes.txt:hidden",
    "ENV~1",
    ".env ",
    "../../../../escape-09.txt",
];

/// Generate the full 50-task suite deterministically.
pub fn generate(seed: u64) -> Vec<Scenario> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::with_capacity(50);

    // 1. Normal Multi-Step (15): 2-3 writes + a charge on even ids.
    for i in 0..15 {
        let mut steps = Vec::new();
        let nfiles = 2 + rng.below(2);
        for f in 0..nfiles {
            steps.push(Step::Write {
                rel: format!("normal-{i:02}/file{f}.txt"),
                content: format!("legit payload {i}-{f}"),
            });
        }
        if i % 2 == 0 {
            steps.push(Step::Charge {
                id: format!("pay-normal-{i:02}"),
                amount: 100 + (rng.below(900) as u64),
            });
        }
        out.push(Scenario {
            id: format!("normal-{i:02}"),
            category: Category::NormalMultiStep,
            steps,
            idem_key: None,
        });
    }

    // 2. Crash & Midway Failure (15): 3-5 steps, crash strictly inside.
    for i in 0..15 {
        let total = 3 + rng.below(3);
        let crash_at = 1 + rng.below(total - 1);
        let mut steps = Vec::new();
        for s in 0..total {
            if s == crash_at {
                steps.push(Step::Crash {
                    reason: CRASH_REASONS[rng.below(CRASH_REASONS.len())],
                });
            } else if s % 2 == 0 {
                steps.push(Step::Write {
                    rel: format!("crash-{i:02}/file{s}.txt"),
                    content: format!("doomed payload {i}-{s}"),
                });
            } else {
                steps.push(Step::Charge {
                    id: format!("pay-crash-{i:02}-{s}"),
                    amount: 250,
                });
            }
        }
        out.push(Scenario {
            id: format!("crash-{i:02}"),
            category: Category::CrashMidway,
            steps,
            idem_key: None,
        });
    }

    // 3. Adversarial Injections (10): one hostile write each.
    for (i, payload) in ADVERSARIAL_PAYLOADS.iter().enumerate() {
        out.push(Scenario {
            id: format!("adversarial-{i:02}"),
            category: Category::Adversarial,
            steps: vec![Step::Write {
                rel: payload.replace("{i}", &format!("{i:02}")),
                content: String::from("injected"),
            }],
            idem_key: None,
        });
    }

    // 4. Flaky Network Retries (10): write + charge, executed twice, one key.
    for i in 0..10 {
        out.push(Scenario {
            id: format!("flaky-{i:02}"),
            category: Category::FlakyRetry,
            steps: vec![
                Step::Write {
                    rel: format!("flaky-{i:02}/order.txt"),
                    content: format!("order {i:02}"),
                },
                Step::Charge {
                    id: format!("pay-flaky-{i:02}"),
                    amount: 250,
                },
            ],
            idem_key: Some(format!("flaky-key-{i:02}")),
        });
    }

    out
}
