//! STRESS TEST 3 — Security fuzzing: 1.000+ input ostili.
//!
//! Path traversal profondi, slash/backslash misti, null byte, control chars,
//! device riservati Windows, domini spoofati e IP in notazioni alternative.
//! Atteso: 100% neutralizzato, MAI un panic, MAI un accesso consentito.

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use sagashield::{KernelError, SecurityGuard, SecurityPolicy};

fn fuzz_policy(workspace: &Path) -> SecurityPolicy {
    SecurityPolicy::new(
        vec![workspace.to_path_buf()],
        vec![
            ".env".to_owned(),
            ".git".to_owned(),
            "id_rsa".to_owned(),
            "id_ed25519".to_owned(),
            "credentials".to_owned(),
        ],
        vec!["api.stripe.com".to_owned(), "api.openai.com".to_owned()],
    )
}

fn fuzz_workspace(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ak_fuzz_{name}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create fuzz workspace");
    dir
}

/// Corpus path ostili (tutti DEVONO essere rifiutati).
fn hostile_paths(ws: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let ws_str = ws.to_string_lossy().to_string();

    // Traversal profondi `../` (profondità 1..=550).
    for n in 1..=550 {
        v.push(format!("{}secret.txt", "../".repeat(n)));
    }
    // Backslash Windows `..\` (profondità 1..=300).
    for n in 1..=300 {
        v.push(format!("{}secret.txt", "..\\".repeat(n)));
    }
    // Misti slash/backslash con processo netto verso l'alto.
    for n in 1..=50 {
        v.push(format!("{}x.txt", "..\\..//../".repeat(n)));
        v.push(format!("..\\{}/..\\calcio.txt", "../".repeat(n)));
    }
    // Assoluti fuori sandbox + UNC.
    v.push("/etc/shadow".to_owned());
    v.push("/etc/passwd".to_owned());
    v.push("C:\\Windows\\System32\\evil.exe".to_owned());
    v.push("C:/Windows/Temp/evil.tmp".to_owned());
    v.push("\\\\server\\share\\evil.txt".to_owned());
    v.push("//server/share/evil.txt".to_owned());
    // Null byte e control chars.
    v.push("ok.txt\0".to_owned());
    v.push("a\0b.txt".to_owned());
    v.push("\0".to_owned());
    v.push("x\r\ny.txt".to_owned());
    v.push("a\tb.txt".to_owned());
    v.push("....//....//etc/shadow".to_owned());
    v.push("a/".repeat(600) + "escape.txt");
    // Device riservati Windows (bare, estesi, nel workspace, con ADS).
    let mut devices = vec!["CON", "PRN", "AUX", "NUL"];
    for i in 1..=9 {
        devices.push(Box::leak(format!("COM{i}").into_boxed_str()) as &str);
        devices.push(Box::leak(format!("LPT{i}").into_boxed_str()) as &str);
    }
    for d in &devices {
        v.push(d.to_string());
        v.push(format!("{d}.txt"));
        v.push(format!("{d}:evil"));
        v.push(format!("{}/{d}", ws_str.replace('\\', "/")));
        v.push(d.to_lowercase());
    }
    // Pattern sensibili (bare e dentro il workspace).
    for s in [
        ".env",
        ".git/config",
        "id_rsa",
        "id_ed25519",
        "credentials.json",
    ] {
        v.push(s.to_owned());
        v.push(format!("{ws_str}/{s}"));
    }
    v.push(format!("{ws_str}/my-credentials-backup.txt"));
    v
}

/// Corpus domini ostili (tutti DEVONO essere rifiutati).
fn hostile_domains() -> Vec<String> {
    let mut v = vec![
        "api.stripe.com.attacker.com".to_owned(),
        "api.openai.com.evil.io".to_owned(),
        "evil-stripe.com".to_owned(),
        "api-stripe.com".to_owned(),
        "apistripe.com".to_owned(),
        "stripe-api.com".to_owned(),
        "openai-api.evil.com".to_owned(),
        "https://api.stripe.com@evil.com".to_owned(),
        "https://api.stripe.com:443@evil.com".to_owned(),
        "http://127.0.0.1/".to_owned(),
        "http://0177.0.0.1/".to_owned(),
        "http://0x7f.0.0.1/".to_owned(),
        "http://2130706433/".to_owned(),
        "http://0x7F000001/".to_owned(),
        "https://[::1]/".to_owned(),
        "evil.com:443".to_owned(),
        "attacker.io/v1".to_owned(),
        "EVIL.COM".to_owned(),
    ];
    for i in 0..200 {
        v.push(format!("evil{i}.attacker.com"));
        v.push(format!("api.stripe.com.evil{i}.com"));
    }
    v
}

#[test]
fn fuzz_paths_blocked_100_percent() {
    let ws = fuzz_workspace("paths");
    let policy = fuzz_policy(&ws);
    let corpus = hostile_paths(&ws);
    assert!(corpus.len() > 950, "corpus path: {}", corpus.len());

    let mut blocked = 0;
    for input in &corpus {
        // catch_unwind: un panic qui è un fallimento del guardrail.
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
            policy.check_path_access(Path::new(input))
        }));
        match r {
            Ok(Ok(p)) => panic!("HOLE! path ostile consentito: {input:?} → {p:?}"),
            Ok(Err(_)) => blocked += 1,
            Err(_) => panic!("PANIC del guard su input: {input:?}"),
        }
    }
    assert_eq!(blocked, corpus.len());

    // Controlli legittimi restano consentiti (niente over-blocking).
    assert!(policy.check_path_access(&ws.join("output.txt")).is_ok());
    assert!(
        policy
            .check_path_access(&ws.join("sub/dir/output.txt"))
            .is_ok()
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn fuzz_domains_blocked_100_percent() {
    let ws = fuzz_workspace("domains");
    let policy = fuzz_policy(&ws);
    let corpus = hostile_domains();

    let mut blocked = 0;
    for input in &corpus {
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| policy.check_network_access(input)));
        match r {
            Ok(Ok(())) => panic!("HOLE! dominio ostile consentito: {input:?}"),
            Ok(Err(e)) => {
                assert!(
                    matches!(
                        &e,
                        KernelError::UnauthorizedNetworkAccess(_)
                            | KernelError::SecurityViolation(_)
                    ),
                    "errore inatteso per {input:?}: {e}"
                );
                blocked += 1;
            }
            Err(_) => panic!("PANIC del guard su dominio: {input:?}"),
        }
    }
    assert_eq!(blocked, corpus.len());

    // Whitelist legittima: nudo, URL, sottodominio, porta.
    assert!(policy.check_network_access("api.openai.com").is_ok());
    assert!(
        policy
            .check_network_access("https://api.stripe.com/v1/charges")
            .is_ok()
    );
    assert!(policy.check_network_access("sub.api.openai.com").is_ok());
    assert!(policy.check_network_access("api.stripe.com:443").is_ok());

    // Banco totale ostile oltre i 1.000 input.
    assert!(corpus.len() + hostile_paths(&ws).len() > 1000);

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn fuzz_garbage_never_panics() {
    let ws = fuzz_workspace("garbage");
    let policy = fuzz_policy(&ws);
    let mut garbage = vec![
        "".to_owned(),
        " ".to_owned(),
        ".".to_owned(),
        "..".to_owned(),
        "/".to_owned(),
        "\\".to_owned(),
        "http://".to_owned(),
        "://".to_owned(),
        "\r\n".to_owned(),
        "nul".to_owned(),
        "COM9:".to_owned(),
        "CON.txt".to_owned(),
        "😈../../\0".to_owned(),
        "A".repeat(20_000),
        "\0".repeat(100),
        "a/".repeat(2000),
        "../".repeat(2000),
    ];
    for evil in hostile_domains().into_iter().take(50) {
        garbage.push(format!("{evil}\0.evil"));
    }

    for input in &garbage {
        let r1 = std::panic::catch_unwind(AssertUnwindSafe(|| {
            policy.check_path_access(Path::new(input))
        }));
        assert!(r1.is_ok(), "PANIC path su {input:?}");
        let r2 = std::panic::catch_unwind(AssertUnwindSafe(|| policy.check_network_access(input)));
        assert!(r2.is_ok(), "PANIC network su {input:?}");
    }

    let _ = std::fs::remove_dir_all(&ws);
}
