//! Binario MCP: `sagashield-mcp` — JSON-RPC 2.0 su stdio.
//!
//! Lettura da stdin, risposte su stdout (riga per messaggio).
//! I log vanno su stderr: stdout è protocollo puro.

use std::path::PathBuf;
use std::sync::Arc;

use sagashield::{McpServer, SecurityPolicy, Wal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // stderr: stdout è riservato al protocollo MCP.
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    let cwd = std::env::current_dir()?;
    let workspace: PathBuf = cwd.join("workspace");
    std::fs::create_dir_all(&workspace)?;

    let policy = SecurityPolicy::new(
        vec![workspace],
        vec![
            ".env".to_owned(),
            ".git".to_owned(),
            "id_rsa".to_owned(),
            "id_ed25519".to_owned(),
            "credentials".to_owned(),
        ],
        vec!["api.stripe.com".to_owned(), "api.openai.com".to_owned()],
    );

    let wal = Arc::new(Wal::open(cwd.join("sagashield-mcp.db"))?);
    let mut server = McpServer::new(wal, Arc::new(policy))?;
    server.serve_stdio().await?;
    Ok(())
}
