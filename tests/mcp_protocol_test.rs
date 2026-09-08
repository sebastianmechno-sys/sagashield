//! Test protocollo MCP: client simulato via stringhe JSON-RPC in memoria.
//!
//! Test 1: handshake `initialize` → risposta JSON-RPC corretta.
//! Test 2: `tools/list` → tool esposti con schemi validi.
//! Test 3: `tools/call` legittimo (`fs_write`) → esecuzione e risposta.
//! Test 4: `tools/call` malevolo (path traversal) → `isError: true`, Step 0.

use std::path::PathBuf;
use std::sync::Arc;

use sagashield::{McpServer, SecurityGuard, SecurityPolicy, Wal};
use serde_json::{Value, json};

fn test_server() -> (McpServer, PathBuf) {
    let ws = std::env::temp_dir().join(format!("ak_mcp_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&ws).expect("create mcp workspace");
    let wal = Arc::new(Wal::open_in_memory().expect("open wal"));
    let guard: Arc<dyn SecurityGuard> = Arc::new(SecurityPolicy::new(
        vec![ws.clone()],
        vec![
            ".env".to_owned(),
            ".git".to_owned(),
            "id_rsa".to_owned(),
            "id_ed25519".to_owned(),
            "credentials".to_owned(),
        ],
        vec!["api.stripe.com".to_owned(), "api.openai.com".to_owned()],
    ));
    let server = McpServer::new(wal, guard).expect("create server");
    (server, ws)
}

/// Invia una richiesta e ritorna la risposta parsata (None = notifica).
async fn rpc(server: &mut McpServer, method: &str, id: i64, params: Value) -> Option<Value> {
    let line = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string();
    server
        .handle_message(&line)
        .await
        .map(|resp| serde_json::from_str(&resp).expect("valid json response"))
}

#[tokio::test]
async fn mcp_initialize_handshake() {
    let (mut server, ws) = test_server();

    let resp = rpc(
        &mut server,
        "initialize",
        1,
        json!({"protocolVersion":"2024-11-05"}),
    )
    .await
    .expect("initialize risponde");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert_eq!(resp["result"]["serverInfo"]["name"], "sagashield-mcp");
    assert_eq!(resp["result"]["serverInfo"]["version"], "0.1.0");

    // Notifica di handshake: nessuna risposta, server vivo.
    let none = server
        .handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    assert!(none.is_none());

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_tools_list_exposes_schemas() {
    let (mut server, ws) = test_server();

    let resp = rpc(&mut server, "tools/list", 2, json!({}))
        .await
        .expect("tools/list risponde");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 10);

    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert!(names.contains(&"fs_write"));
    assert!(names.contains(&"mock_pay"));
    assert!(names.contains(&"kernel_status"));
    assert!(names.contains(&"agent_kernel_exec"));
    assert!(names.contains(&"kernel_replay_session"));
    assert!(names.contains(&"kernel_export_audit"));
    assert!(names.contains(&"kernel_list_dlq"));
    assert!(names.contains(&"kernel_approve_action"));
    assert!(names.contains(&"kernel_reject_action"));
    assert!(names.contains(&"kernel_prune_history"));

    for tool in tools {
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "schema {}",
            tool["name"]
        );
        assert!(tool["description"].is_string());
    }
    let fs = tools
        .iter()
        .find(|t| t["name"] == "fs_write")
        .expect("fs_write");
    assert!(
        fs["inputSchema"]["required"]
            .as_array()
            .expect("required")
            .contains(&json!("path"))
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_call_legit_fs_write_executes() {
    let (mut server, ws) = test_server();
    let path = ws.join("hello.txt").to_string_lossy().to_string();

    let resp = rpc(
        &mut server,
        "tools/call",
        3,
        json!({"name":"fs_write","arguments":{"path":path,"content":"mcp was here"}}),
    )
    .await
    .expect("tools/call risponde");

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 3);
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("fs_write OK"), "testo: {text}");
    assert!(std::path::Path::new(&path).exists(), "file scritto davvero");

    // kernel_status riflette la saga (stato + azione COMMITTED).
    let status = rpc(
        &mut server,
        "tools/call",
        4,
        json!({"name":"kernel_status","arguments":{}}),
    )
    .await
    .expect("status risponde");
    let status_text = status["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(status_text.contains("Verifying"), "stato: {status_text}");

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_call_traversal_blocked_at_step_zero() {
    let (mut server, ws) = test_server();

    let resp = rpc(
        &mut server,
        "tools/call",
        5,
        json!({"name":"fs_write","arguments":{"path":"../../.env","content":"pwned"}}),
    )
    .await
    .expect("tools/call risponde anche sotto attacco");

    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.to_lowercase().contains("ecurity"),
        "atteso dettaglio violazione, ottenuto: {text}"
    );

    // Step 0: nessuna riga WAL per la saga, nessun file creato fuori sandbox.
    let session = server.session_id().to_string();
    let actions = server.wal().get_actions(&session).expect("read wal");
    assert!(actions.is_empty(), "Step 0 non scrive sul WAL: {actions:?}");

    // Il server non è crashato: chiamata successiva legittima funziona.
    let ok_path = ws.join("after.txt").to_string_lossy().to_string();
    let again = rpc(
        &mut server,
        "tools/call",
        6,
        json!({"name":"fs_write","arguments":{"path":ok_path,"content":"alive"}}),
    )
    .await
    .expect("server ancora vivo");
    assert_eq!(again["result"]["isError"], false);

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_protocol_errors() {
    let (mut server, ws) = test_server();

    // Metodo ignoto → -32601.
    let resp = rpc(&mut server, "nope/unknown", 7, json!({}))
        .await
        .expect("errore di protocollo");
    assert_eq!(resp["error"]["code"], -32601);

    // Tool ignoto → -32602.
    let resp = rpc(
        &mut server,
        "tools/call",
        8,
        json!({"name":"rm_rf","arguments":{}}),
    )
    .await
    .expect("errore tool ignoto");
    assert_eq!(resp["error"]["code"], -32602);

    // Parse error → -32700.
    let raw = server
        .handle_message("{not json")
        .await
        .expect("parse error");
    let parsed: Value = serde_json::from_str(&raw).expect("json");
    assert_eq!(parsed["error"]["code"], -32700);

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_gateway_executes_protected_intent() {
    let (mut server, ws) = test_server();
    let path = ws.join("gw.txt").to_string_lossy().to_string();

    // Intent legittimo via gateway (nome stile kernel + sessione esplicita).
    let sid = uuid::Uuid::new_v4().to_string();
    let resp = rpc(
        &mut server,
        "tools/call",
        10,
        json!({"name":"agent_kernel_exec","arguments":{
            "tool_name": "fs.write",
            "parameters": {"path": path, "content": "via gateway"},
            "session_id": sid,
        }}),
    )
    .await
    .expect("gateway risponde");
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.contains("agent_kernel_exec(fs.write) OK"),
        "testo: {text}"
    );
    assert!(std::path::Path::new(&path).exists());

    // WAL tracciato sotto la sessione fornita.
    let actions = server.wal().get_actions(&sid).expect("read wal");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].tool_id, "fs.write");

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_gateway_blocks_malicious_intent() {
    let (mut server, ws) = test_server();

    // Path traversal via gateway → isError + Step 0 (WAL vuoto).
    let resp = rpc(
        &mut server,
        "tools/call",
        11,
        json!({"name":"agent_kernel_exec","arguments":{
            "tool_name": "fs_write",
            "parameters": {"path": "../../.env", "content": "pwned"},
        }}),
    )
    .await
    .expect("gateway risponde anche sotto attacco");
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.to_lowercase().contains("ecurity"), "testo: {text}");
    assert!(
        server
            .wal()
            .get_actions(&server.session_id().to_string())
            .expect("read wal")
            .is_empty()
    );

    // tool_name ignoto e session_id invalido → isError diagnostici.
    let bad_tool = rpc(
        &mut server,
        "tools/call",
        12,
        json!({"name":"agent_kernel_exec","arguments":{
            "tool_name": "rm_rf", "parameters": {}}}),
    )
    .await
    .expect("gateway tool ignoto");
    assert_eq!(bad_tool["result"]["isError"], true);

    let bad_sid = rpc(
        &mut server,
        "tools/call",
        13,
        json!({"name":"agent_kernel_exec","arguments":{
            "tool_name": "mock_pay",
            "parameters": {},
            "session_id": "not-a-uuid"}}),
    )
    .await
    .expect("gateway session invalida");
    assert_eq!(bad_sid["result"]["isError"], true);

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn mcp_maintenance_tools_dlq_prune_approve() {
    let (mut server, ws) = test_server();

    // DLQ vuota → lista JSON vuota, nessun errore.
    let dlq = rpc(
        &mut server,
        "tools/call",
        20,
        json!({"name":"kernel_list_dlq","arguments":{}}),
    )
    .await
    .expect("dlq risponde");
    assert_eq!(dlq["result"]["isError"], false);
    assert_eq!(dlq["result"]["content"][0]["text"], "[]");

    // Approve su sessione sconosciuta → isError diagnostico, server vivo.
    let sid = uuid::Uuid::new_v4().to_string();
    let deny = rpc(
        &mut server,
        "tools/call",
        21,
        json!({"name":"kernel_approve_action","arguments":{"session_id":sid,"token":"nope"}}),
    )
    .await
    .expect("approve risponde");
    assert_eq!(deny["result"]["isError"], true);

    // Prune senza giorni → isError; con 365 → report testuale OK.
    let bad_prune = rpc(
        &mut server,
        "tools/call",
        22,
        json!({"name":"kernel_prune_history","arguments":{}}),
    )
    .await
    .expect("prune invalido risponde");
    assert_eq!(bad_prune["result"]["isError"], true);

    let prune = rpc(
        &mut server,
        "tools/call",
        23,
        json!({"name":"kernel_prune_history","arguments":{"older_than_days":365}}),
    )
    .await
    .expect("prune risponde");
    assert_eq!(prune["result"]["isError"], false);
    let text = prune["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.contains("Pruned"), "report atteso, ottenuto: {text}");

    let _ = std::fs::remove_dir_all(&ws);
}
