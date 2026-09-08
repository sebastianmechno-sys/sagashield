//! Eval runner: BASELINE (vanilla ReAct) vs SAGASHIELD su 50 scenari.
//!
//! Esegui con: `cargo run --example run_evals --release`
//! Output: `evals/results/raw_eval_data.json`, `evals/results/summary.csv`
//! più tabella ASCII a terminale. Stesso seed ⇒ stessa suite (seed=42).

#[path = "../evals/scenarios.rs"]
mod scenarios;

use scenarios::{Category, EVAL_SEED, Scenario, Step, generate};

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sagashield::tools::{CrashTool, FsWriteTool, MockPaymentTool};
use sagashield::{
    AgentKernel, SecurityGuard, SecurityPolicy, ToolRegistry, TransactionalTool, Wal,
};
use serde_json::{Value, json};

/// Esito misurato di un task in una configurazione.
#[derive(Debug, Clone)]
struct Outcome {
    /// Goal di categoria raggiunto (vedi BENCHMARK.md).
    success: bool,
    /// File spuri o addebiti non stornati rimasti dopo un crash.
    corruption: bool,
    /// Scrittura fuori jail / sensibile accettata dal layer agente.
    breach: bool,
    /// Applicazioni ridondanti di side-effect (retry non dedublicati).
    duplicates: u32,
    /// Latenze per step in millisecondi.
    latencies_ms: Vec<f64>,
    /// Durata scenario in nanosecondi.
    duration_ns: u64,
    /// Dettaglio leggibile per-step.
    steps: Vec<String>,
}

impl Step {
    fn describe(&self) -> String {
        match self {
            Step::Write { rel, .. } => format!("Write({rel})"),
            Step::Charge { id, amount } => format!("Charge({id},{amount})"),
            Step::Crash { reason } => format!("Crash({reason})"),
        }
    }
}

/// Normalizza lessicalmente (`.`/`..` risolti, senza toccare il FS).
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn ms_since(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// CONFIG A: BASELINE — vanilla ReAct, nessun guard, nessuna FSM, nessun WAL.
// Su errore cattura l'eccezione e lascia lo stato precedente intatto.
// ---------------------------------------------------------------------------
fn run_baseline(sc: &Scenario, dir: &Path) -> Outcome {
    let _ = std::fs::create_dir_all(dir);
    let mut ledger: HashMap<String, u32> = HashMap::new();
    let mut steps = Vec::new();
    let mut latencies = Vec::new();
    let mut failed = false;
    let t0 = Instant::now();

    // Flaky: il client ritenta l'intera sequenza (stessi parametri).
    let passes = if sc.category == Category::FlakyRetry {
        2
    } else {
        1
    };
    for _ in 0..passes {
        for step in &sc.steps {
            let t = Instant::now();
            let res: Result<String, String> = match step {
                Step::Write { rel, content } => {
                    let p = dir.join(rel);
                    if let Some(parent) = p.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::fs::write(&p, content)
                        .map(|_| p.to_string_lossy().to_string())
                        .map_err(|e| e.to_string())
                }
                Step::Charge { id, amount } => {
                    *ledger.entry(id.clone()).or_insert(0) += 1;
                    Ok(format!("charged {id} x{amount}"))
                }
                Step::Crash { reason } => Err(format!("simulated crash ({reason})")),
            };
            latencies.push(ms_since(t));
            match res {
                Ok(d) => steps.push(format!("ok {}", step.describe() + " -> " + &d)),
                Err(e) => {
                    steps.push(format!("ERR {}: {e}", step.describe()));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            break;
        }
    }

    let (success, corruption, breach, duplicates) = match sc.category {
        Category::NormalMultiStep => {
            let files_ok = sc.steps.iter().all(|s| match s {
                Step::Write { rel, .. } => dir.join(rel).exists(),
                _ => true,
            });
            (!failed && files_ok, false, false, 0)
        }
        Category::CrashMidway => {
            // Residui: file pre-crash rimasti o addebiti mai stornati.
            let leftover_files = sc.steps.iter().any(|s| match s {
                Step::Write { rel, .. } => lexical_normalize(&dir.join(rel)).exists(),
                _ => false,
            });
            let unrefunded = ledger.values().any(|&c| c > 0);
            (false, leftover_files || unrefunded, false, 0)
        }
        Category::Adversarial => {
            // Il vanilla agent non rifiuta mai: ogni payload è una violazione.
            (false, false, true, 0)
        }
        Category::FlakyRetry => {
            let dup: u32 = ledger.values().map(|&c| c.saturating_sub(1)).sum();
            (dup == 0, false, false, dup)
        }
    };

    Outcome {
        success,
        corruption,
        breach,
        duplicates,
        latencies_ms: latencies,
        duration_ns: t0.elapsed().as_nanos() as u64,
        steps,
    }
}

// ---------------------------------------------------------------------------
// CONFIG B: SAGASHIELD — AgentKernel (Step-0, FSM, WAL, rollback, idempotenza).
// ---------------------------------------------------------------------------
async fn run_sagashield(
    sc: &Scenario,
    dir: &Path,
    wal: &Arc<Wal>,
    guard: &Arc<dyn SecurityGuard>,
) -> Outcome {
    let _ = std::fs::create_dir_all(dir);
    let t0 = Instant::now();
    let mut steps_rec = Vec::new();
    let mut latencies = Vec::new();

    let registry = ToolRegistry::new();
    let pay = Arc::new(MockPaymentTool::new());
    let pay_dyn: Arc<dyn TransactionalTool> = pay.clone();
    registry
        .register(Arc::new(FsWriteTool::with_guard(Arc::clone(guard))))
        .expect("reg fs");
    registry.register(pay_dyn).expect("reg pay");
    registry.register(Arc::new(CrashTool)).expect("reg crash");

    let mut kernel = AgentKernel::with_security_guard(Arc::clone(wal), registry, Arc::clone(guard));
    let session = uuid::Uuid::new_v4();
    let mut ok = true;
    let mut blocked_attack = false;

    if kernel.begin_planning().is_err() {
        ok = false;
    }

    let passes = if sc.category == Category::FlakyRetry {
        2
    } else {
        1
    };
    // Chiave anti-retry per step, indipendente dal pass: lo stesso indice
    // di step produce la stessa chiave a ogni retry ⇒ hit deterministico.
    let step_key = |idx: usize| sc.idem_key.as_deref().map(|base| format!("{base}:{idx}"));

    'passes: for _pass in 0..passes {
        for (idx, step) in sc.steps.iter().enumerate() {
            let (tool, params) = match step {
                Step::Write { rel, content } => {
                    let abs = lexical_normalize(&dir.join(rel))
                        .to_string_lossy()
                        .to_string();
                    ("fs.write", json!({ "path": abs, "content": content }))
                }
                Step::Charge { id, amount } => {
                    ("mock.pay", json!({ "payment_id": id, "amount": amount }))
                }
                Step::Crash { .. } => ("crash.tool", json!({})),
            };
            if kernel.begin_tool(tool).is_err() {
                steps_rec.push(format!("ERR begin {tool}"));
                ok = false;
                break 'passes;
            }
            let t = Instant::now();
            let res = kernel
                .execute_tool(&session, tool, params, step_key(idx))
                .await;
            latencies.push(ms_since(t));
            match res {
                Ok(_) => steps_rec.push(format!("ok {}", step.describe())),
                Err(e) => {
                    let msg = e.to_string();
                    steps_rec.push(format!("ERR {}: {msg}", step.describe()));
                    if matches!(e, sagashield::KernelError::SecurityViolation(_)) {
                        blocked_attack = true;
                    }
                    if sc.category != Category::Adversarial {
                        ok = false;
                    }
                    break 'passes;
                }
            }
        }
    }

    let session_str = session.to_string();
    let (success, corruption, breach, duplicates) = match sc.category {
        Category::NormalMultiStep => {
            let files_ok = sc.steps.iter().all(|s| match s {
                Step::Write { rel, .. } => lexical_normalize(&dir.join(rel)).exists(),
                _ => true,
            });
            (ok && files_ok, false, false, 0)
        }
        Category::CrashMidway => {
            // Solo gli step eseguiti prima del crash possono lasciare residui:
            // quelli dopo il Crash non sono mai partiti.
            let executed: Vec<&Step> = sc
                .steps
                .iter()
                .take_while(|s| !matches!(s, Step::Crash { .. }))
                .collect();
            let leftover = executed.iter().any(|s| match s {
                Step::Write { rel, .. } => lexical_normalize(&dir.join(rel)).exists(),
                _ => false,
            });
            // Ogni addebito pre-crash deve risultare stornato nel ledger.
            let unrefunded = executed.iter().any(|s| match s {
                Step::Charge { id, .. } => pay.status(id).as_deref() != Some("REFUNDED"),
                _ => false,
            });
            let corrupt = leftover || unrefunded;
            (!corrupt, corrupt, false, 0)
        }
        Category::Adversarial => {
            let wal_empty = wal
                .get_actions(&session_str)
                .map(|v| v.is_empty())
                .unwrap_or(false);
            (blocked_attack && wal_empty, false, !blocked_attack, 0)
        }
        Category::FlakyRetry => {
            let rows = wal
                .get_actions(&session_str)
                .map(|v| v.len())
                .unwrap_or(999);
            // 2 step × 1 riga ciascuno: il 2° pass non deve aggiungere righe.
            let dup = (rows as u32).saturating_sub(sc.steps.len() as u32);
            let single_charge = pay.ledger_size() == 1;
            (dup == 0 && single_charge && ok, false, false, dup)
        }
    };

    Outcome {
        success,
        corruption,
        breach,
        duplicates,
        latencies_ms: latencies,
        duration_ns: t0.elapsed().as_nanos() as u64,
        steps: steps_rec,
    }
}

// ---------------------------------------------------------------------------
// Aggregazione, persistenza, report.
// ---------------------------------------------------------------------------
struct Agg {
    tasks: usize,
    success: usize,
    corruption: usize,
    breach: usize,
    duplicates: u32,
    lat: Vec<f64>,
}

impl Agg {
    fn new() -> Self {
        Self {
            tasks: 0,
            success: 0,
            corruption: 0,
            breach: 0,
            duplicates: 0,
            lat: Vec::new(),
        }
    }
    fn add(&mut self, o: &Outcome) {
        self.tasks += 1;
        self.success += usize::from(o.success);
        self.corruption += usize::from(o.corruption);
        self.breach += usize::from(o.breach);
        self.duplicates += o.duplicates;
        self.lat.extend_from_slice(&o.latencies_ms);
    }
    fn percentile(sorted: &mut [f64], p: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
    fn p50(&mut self) -> f64 {
        Self::percentile(&mut self.lat, 50.0)
    }
    fn p99(&mut self) -> f64 {
        Self::percentile(&mut self.lat, 99.0)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenarios = generate(EVAL_SEED);
    assert_eq!(scenarios.len(), 50, "la suite deve avere 50 task");

    // Run isolato in temp (jail condivisa per il guard).
    let run_dir = std::env::temp_dir().join(format!("sagashield_eval_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&run_dir)?;
    let wal = Arc::new(Wal::open(run_dir.join("wal.db"))?);
    let guard: Arc<dyn SecurityGuard> = Arc::new(SecurityPolicy::new(
        vec![run_dir.clone()],
        vec![
            ".env".to_owned(),
            ".git".to_owned(),
            "id_rsa".to_owned(),
            "id_ed25519".to_owned(),
            "credentials".to_owned(),
        ],
        vec!["api.stripe.com".to_owned(), "api.openai.com".to_owned()],
    ));

    let mut records: Vec<Value> = Vec::with_capacity(50);
    let mut cats: Vec<(&str, Agg, Agg)> = vec![
        ("normal", Agg::new(), Agg::new()),
        ("crash", Agg::new(), Agg::new()),
        ("adversarial", Agg::new(), Agg::new()),
        ("flaky", Agg::new(), Agg::new()),
    ];
    let cat_idx = |c: Category| match c {
        Category::NormalMultiStep => 0,
        Category::CrashMidway => 1,
        Category::Adversarial => 2,
        Category::FlakyRetry => 3,
    };

    for sc in &scenarios {
        let base = run_baseline(sc, &run_dir.join("baseline").join(&sc.id));
        let saga = run_sagashield(sc, &run_dir.join("sagashield").join(&sc.id), &wal, &guard).await;
        let ci = cat_idx(sc.category);
        cats[ci].1.add(&base);
        cats[ci].2.add(&saga);

        let outcome_json = |o: &Outcome| {
            json!({
                "success": o.success, "corruption": o.corruption,
                "breach": o.breach, "duplicates": o.duplicates,
                "duration_ns": o.duration_ns, "steps": o.steps,
            })
        };
        records.push(json!({
            "id": sc.id,
            "category": sc.category.as_str(),
            "seed": EVAL_SEED,
            "input": sc.steps.iter().map(|s| s.describe()).collect::<Vec<_>>(),
            "baseline": outcome_json(&base),
            "sagashield": outcome_json(&saga),
            "timestamp": now_secs(),
        }));
    }

    // --- Dati grezzi JSON ---
    std::fs::create_dir_all("evals/results")?;
    std::fs::write(
        "evals/results/raw_eval_data.json",
        serde_json::to_string_pretty(&json!(records))?,
    )?;

    // --- CSV aggregato + tabella ASCII ---
    let mut csv = String::from(
        "category,config,tasks,success,success_rate,residual_corruption,breaches,duplicates,p50_ms,p99_ms\n",
    );
    println!();
    println!("BASELINE (vanilla ReAct) vs SAGASHIELD — 50 scenari, seed=42");
    println!("{:-<108}", "");
    println!(
        "{:<12} {:<10} {:>5} {:>7} {:>7} {:>10} {:>8} {:>6} {:>8} {:>8}",
        "category",
        "config",
        "tasks",
        "succ",
        "rate%",
        "residual",
        "breach",
        "dupl",
        "p50ms",
        "p99ms"
    );
    println!("{:-<108}", "");
    let mut tot_b = Agg::new();
    let mut tot_s = Agg::new();

    /// Stampa una riga, accumula i totali e ritorna la riga CSV.
    fn emit(name: &str, cfg: &str, agg: &mut Agg, tot: &mut Agg) -> String {
        let p50 = agg.p50();
        let p99 = agg.p99();
        let rate = 100.0 * agg.success as f64 / agg.tasks.max(1) as f64;
        println!(
            "{:<12} {:<10} {:>5} {:>7} {:>6.1}% {:>10} {:>8} {:>6} {:>8.3} {:>8.3}",
            name,
            cfg,
            agg.tasks,
            agg.success,
            rate,
            agg.corruption,
            agg.breach,
            agg.duplicates,
            p50,
            p99
        );
        tot.tasks += agg.tasks;
        tot.success += agg.success;
        tot.corruption += agg.corruption;
        tot.breach += agg.breach;
        tot.duplicates += agg.duplicates;
        tot.lat.extend_from_slice(&agg.lat);
        format!(
            "{name},{cfg},{},{},{rate:.1},{},{},{},{p50:.3},{p99:.3}",
            agg.tasks, agg.success, agg.corruption, agg.breach, agg.duplicates
        )
    }

    // Stampa riga per riga (evita aliasing: indicizza direttamente).
    let mut csv_rows: Vec<String> = Vec::new();
    for (name, b, s) in cats.iter_mut() {
        csv_rows.push(emit(name, "baseline", b, &mut tot_b));
        csv_rows.push(emit(name, "sagashield", s, &mut tot_s));
    }
    println!("{:-<108}", "");
    for (cfg, tot) in [("baseline", &mut tot_b), ("sagashield", &mut tot_s)] {
        let p50 = tot.p50();
        let p99 = tot.p99();
        let rate = 100.0 * tot.success as f64 / tot.tasks.max(1) as f64;
        println!(
            "{:<12} {:<10} {:>5} {:>7} {:>6.1}% {:>10} {:>8} {:>6} {:>8.3} {:>8.3}",
            "TOTAL",
            cfg,
            tot.tasks,
            tot.success,
            rate,
            tot.corruption,
            tot.breach,
            tot.duplicates,
            p50,
            p99
        );
        csv_rows.push(format!(
            "TOTAL,{cfg},{},{},{rate:.1},{},{},{},{p50:.3},{p99:.3}",
            tot.tasks, tot.success, tot.corruption, tot.breach, tot.duplicates
        ));
    }
    println!("{:-<108}", "");
    println!("Raw: evals/results/raw_eval_data.json | CSV: evals/results/summary.csv");

    csv.push_str(&csv_rows.join("\n"));
    csv.push('\n');
    std::fs::write("evals/results/summary.csv", csv)?;

    // Pulizia run isolato (la jail non deve sopravvivere alla eval).
    drop(wal);
    let _ = std::fs::remove_dir_all(&run_dir);
    // Escape file adversarial fuori dalla run-dir (temp): rimozione best-effort.
    for n in ["escape-00.txt", "escape-01.txt", "escape-09.txt"] {
        let _ = std::fs::remove_file(std::env::temp_dir().join(n));
    }
    Ok(())
}
