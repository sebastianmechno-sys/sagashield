//! Test Fase 4 + hardening NTFS: Sandboxing & Security Guardrail.
//!
//! - Test 1: path traversal → BLOCCATO (`PathTraversalDetected`).
//! - Test 2: file sensibile in cartella autorizzata → BLOCCATO (`BlockedFileAccess`).
//! - Test 3: accesso valido → AUTORIZZATO.
//! - Test 4: dominio malevolo → BLOCCATO (`UnauthorizedNetworkAccess`).
//! - Test 5: kernel blocca allo Step 0 senza DB né mutazione FSM.
//! - Test 6-8 (hardening): ADS (`:`), nomi corti 8.3 (`~N`), trailing dots/spaces.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sagashield::tools::FsWriteTool;
use sagashield::{
    AgentKernel, AgentState, KernelError, SecurityGuard, SecurityPolicy, ToolRegistry,
    TransactionalTool, Wal,
};
use serde_json::json;

fn test_policy(workspace: &Path) -> SecurityPolicy {
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

fn unique_workspace(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ak_sandbox_{name}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create test workspace");
    dir
}

#[test]
fn traversal_attack_is_blocked() -> Result<(), KernelError> {
    let ws = unique_workspace("traversal");
    let policy = test_policy(&ws);

    // `..` che esce dal workspace.
    let escape = ws.join("..").join("..").join("secret.txt");
    let err = policy
        .check_path_access(&escape)
        .expect_err("traversal deve essere bloccato");
    assert!(
        matches!(&err, KernelError::PathTraversalDetected(_)),
        "atteso PathTraversalDetected, ottenuto: {err}"
    );

    // Assoluto fuori sandbox (indipendente dalla piattaforma).
    let outside = std::env::temp_dir().join(format!("ak_outside_{}.txt", uuid::Uuid::new_v4()));
    let err = policy
        .check_path_access(&outside)
        .expect_err("path fuori sandbox deve essere bloccato");
    assert!(
        matches!(
            &err,
            KernelError::PathTraversalDetected(_) | KernelError::SecurityViolation(_)
        ),
        "ottenuto: {err}"
    );

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn sensitive_file_inside_allowed_dir_is_blocked() -> Result<(), KernelError> {
    let ws = unique_workspace("sensitive");
    let policy = test_policy(&ws);

    for name in [".env", "credentials.json", "id_rsa", ".git"] {
        let target = ws.join(name);
        let err = policy
            .check_path_access(&target)
            .expect_err(&format!("{name} deve essere bloccato"));
        assert!(
            matches!(&err, KernelError::BlockedFileAccess(_)),
            "per {name}: atteso BlockedFileAccess, ottenuto: {err}"
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn valid_access_is_authorized() -> Result<(), KernelError> {
    let ws = unique_workspace("valid");
    let policy = test_policy(&ws);

    let ok = policy.check_path_access(&ws.join("output.txt"))?;
    assert!(
        ok.starts_with(&ws),
        "il path validato deve restare nel workspace"
    );

    let nested = ws.join("sub").join("dir").join("output.txt");
    let ok = policy.check_path_access(&nested)?;
    assert!(ok.starts_with(&ws));

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn malicious_network_domain_is_blocked() -> Result<(), KernelError> {
    let ws = unique_workspace("net");
    let policy = test_policy(&ws);

    // Domini malevoli / exfiltration.
    for evil in [
        "https://evil-exfil.example.com/steal",
        "attacker.io",
        "http://malware-c2.net:8080/beacon",
        "api.openai.com.evil.com",
    ] {
        let err = policy
            .check_network_access(evil)
            .expect_err(&format!("{evil} deve essere bloccato"));
        assert!(
            matches!(&err, KernelError::UnauthorizedNetworkAccess(_)),
            "per {evil}: atteso UnauthorizedNetworkAccess, ottenuto: {err}"
        );
    }

    // Whitelist (nudo, URL completo, sottodominio).
    policy.check_network_access("api.openai.com")?;
    policy.check_network_access("https://api.stripe.com/v1/charges")?;
    policy.check_network_access("sub.api.openai.com")?;

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[tokio::test]
async fn kernel_blocks_attack_before_db_and_fsm() -> Result<(), KernelError> {
    let ws = unique_workspace("kernel");
    let policy = test_policy(&ws);
    let guard: Arc<dyn SecurityGuard> = Arc::new(policy);

    let wal = Arc::new(Wal::open_in_memory()?);
    let registry = ToolRegistry::new();
    let fs_dyn: Arc<dyn TransactionalTool> = Arc::new(FsWriteTool::with_guard(Arc::clone(&guard)));
    registry.register(fs_dyn)?;

    let mut kernel =
        AgentKernel::with_security_guard(Arc::clone(&wal), registry, Arc::clone(&guard));
    let session = uuid::Uuid::new_v4();

    // FSM autorizza fs.write, ma lo Step 0 di sicurezza deve bloccare prima.
    kernel.begin_planning()?;
    kernel.begin_tool("fs.write")?;
    assert_eq!(
        kernel.state(),
        &AgentState::ExecutingTool("fs.write".to_owned())
    );

    let evil = ws
        .join("..")
        .join("..")
        .join("escape.txt")
        .to_string_lossy()
        .to_string();
    let err = kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": evil, "content": "pwned" }),
            None,
        )
        .await
        .expect_err("traversal via kernel deve essere bloccato");
    assert!(
        matches!(&err, KernelError::SecurityViolation(_)),
        "atteso SecurityViolation dallo Step 0, ottenuto: {err}"
    );

    // Nessuna riga WAL, FSM immutata (ancora ExecutingTool, non Compensating/Failed).
    assert!(wal.get_actions(&session.to_string())?.is_empty());
    assert_eq!(
        kernel.state(),
        &AgentState::ExecutingTool("fs.write".to_owned())
    );

    // Anche il file sensibile dentro il workspace è bloccato allo Step 0.
    let env_path = ws.join(".env").to_string_lossy().to_string();
    let err = kernel
        .execute_tool(
            &session,
            "fs.write",
            json!({ "path": env_path, "content": "x" }),
            None,
        )
        .await
        .expect_err(".env deve essere bloccato");
    assert!(matches!(&err, KernelError::SecurityViolation(_)));
    assert!(wal.get_actions(&session.to_string())?.is_empty());

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn ads_streams_are_blocked() -> Result<(), KernelError> {
    let ws = unique_workspace("ads");
    let policy = test_policy(&ws);

    // Alternate Data Streams: mai nomi file legittimi, sempre sospetti.
    for name in ["notes.txt:hidden", "photo.jpg:evil", ".env:stream"] {
        let target = ws.join(name);
        let err = policy
            .check_path_access(&target)
            .expect_err(&format!("ADS {name} deve essere bloccato"));
        assert!(
            matches!(&err, KernelError::BlockedFileAccess(_)),
            "per {name}: atteso BlockedFileAccess, ottenuto: {err}"
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn short_filenames_are_blocked() -> Result<(), KernelError> {
    let ws = unique_workspace("short");
    let policy = test_policy(&ws);

    // Alias 8.3 (`ENV~1`) che su NTFS possono risolvere a nomi bloccati.
    for name in ["ENV~1", "DOCUME~1", "PROGRA~2", "secrets~9.txt"] {
        let target = ws.join(name);
        let err = policy
            .check_path_access(&target)
            .expect_err(&format!("short name {name} deve essere bloccato"));
        assert!(
            matches!(&err, KernelError::BlockedFileAccess(_)),
            "per {name}: atteso BlockedFileAccess, ottenuto: {err}"
        );
    }

    // Nomi con `~` non numerica restano consentiti (es. backup editor `file~`).
    assert!(policy.check_path_access(&ws.join("notes~")).is_ok());
    assert!(policy.check_path_access(&ws.join("my~backup.txt")).is_ok());

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}

#[test]
fn trailing_dots_and_spaces_are_normalized() -> Result<(), KernelError> {
    let ws = unique_workspace("trailing");
    let policy = test_policy(&ws);

    // Win32 normalizza `.env ` → `.env`: deve scattare la blocklist.
    for name in [".env ", ".env.", ".git ", "credentials.json."] {
        let target = ws.join(name);
        let err = policy.check_path_access(&target).expect_err(&format!(
            "{name:?} deve essere bloccato dopo normalizzazione"
        ));
        assert!(
            matches!(&err, KernelError::BlockedFileAccess(_)),
            "per {name:?}: atteso BlockedFileAccess, ottenuto: {err}"
        );
    }

    // Trailing dot su nome innocuo: consentito (il file resta nel workspace).
    let ok = policy.check_path_access(&ws.join("report.txt."))?;
    assert!(ok.starts_with(&ws));

    let _ = std::fs::remove_dir_all(&ws);
    Ok(())
}
