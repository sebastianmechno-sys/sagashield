//! Server MCP (Model Context Protocol) — JSON-RPC 2.0 su stdio.
//!
//! Espone i tool protetti da SagaShield a qualsiasi client MCP
//! (Claude Desktop, Cursor, Claude Code):
//! `initialize`, `notifications/initialized`, `tools/list`, `tools/call`.
//!
//! Ogni `tools/call` gira dentro una saga di [`AgentKernel`]:
//! blocco Step-0 → FSM → WAL → rollback LIFO automatico.

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::{info, warn};

use crate::dispatcher::{AgentKernel, ToolRegistry};
use crate::error::{KernelError, KernelResult};
use crate::fsm::AgentState;
use crate::security::SecurityGuard;
use crate::tools::{FsWriteTool, MockPaymentTool};
use crate::traits::TransactionalTool;
use crate::types::ActionStatus;
use crate::wal::Wal;

/// Versione di protocollo negoziata con i client.
pub const PROTOCOL_VERSION: &str = "2024-11-05";
/// Nome server annunciato in `serverInfo`.
pub const SERVER_NAME: &str = "sagashield-mcp";

/// Tool MCP `fs_write` → kernel `fs.write` (sandboxed, compensabile).
pub const TOOL_FS_WRITE: &str = "fs_write";
/// Tool MCP `mock_pay` → kernel `mock.pay` (simulato, stornabile).
pub const TOOL_MOCK_PAY: &str = "mock_pay";
/// Tool MCP nativo: stato kernel read-only, nessuna mutazione.
pub const TOOL_STATUS: &str = "kernel_status";
/// Gateway universale: proxy protetto verso qualsiasi tool registrato.
pub const TOOL_GATEWAY: &str = "agent_kernel_exec";
/// Replay deterministico di una sessione passata (dry-run dal WAL).
pub const TOOL_REPLAY: &str = "kernel_replay_session";
/// Export audit OTel di una sessione (JSON per Datadog/Honeycomb/Jaeger).
pub const TOOL_AUDIT: &str = "kernel_export_audit";
/// Ispezione DLQ: compensazioni fallite non risolte (sola lettura).
pub const TOOL_DLQ: &str = "kernel_list_dlq";
/// Approva un'azione irreversibile in attesa (2-Phase Commit).
pub const TOOL_APPROVE: &str = "kernel_approve_action";
/// Rifiuta un'azione irreversibile e compensa il passato.
pub const TOOL_REJECT: &str = "kernel_reject_action";
/// Retention: elimina storia terminale vecchia + vacuum.
pub const TOOL_PRUNE: &str = "kernel_prune_history";

const KERNEL_FS_WRITE: &str = "fs.write";
const KERNEL_MOCK_PAY: &str = "mock.pay";

/// Registry standard del server (fs_write con sandbox + mock_pay).
pub fn default_registry(guard: Arc<dyn SecurityGuard>) -> KernelResult<ToolRegistry> {
    let registry = ToolRegistry::new();
    let fs: Arc<dyn TransactionalTool> = Arc::new(FsWriteTool::with_guard(Arc::clone(&guard)));
    registry.register(fs)?;
    registry.register(Arc::new(MockPaymentTool::new()))?;
    Ok(registry)
}

/// Server MCP stateful: un kernel, una saga corrente, un WAL condiviso.
pub struct McpServer {
    wal: Arc<Wal>,
    guard: Arc<dyn SecurityGuard>,
    kernel: AgentKernel,
    session_id: uuid::Uuid,
}

impl McpServer {
    /// Crea il server (WAL + policy forniti dal chiamante).
    pub fn new(wal: Arc<Wal>, guard: Arc<dyn SecurityGuard>) -> KernelResult<Self> {
        let kernel = AgentKernel::with_security_guard(
            Arc::clone(&wal),
            default_registry(Arc::clone(&guard))?,
            Arc::clone(&guard),
        );
        Ok(Self {
            wal,
            guard,
            kernel,
            session_id: uuid::Uuid::new_v4(),
        })
    }

    /// WAL condiviso (per verifiche nei test).
    pub fn wal(&self) -> &Arc<Wal> {
        &self.wal
    }

    /// ID della saga corrente.
    pub fn session_id(&self) -> uuid::Uuid {
        self.session_id
    }

    /// Nuova saga: kernel fresco + nuova sessione (dopo Completed/Failed).
    fn reset_saga(&mut self) -> KernelResult<()> {
        self.kernel = AgentKernel::with_security_guard(
            Arc::clone(&self.wal),
            default_registry(Arc::clone(&self.guard))?,
            Arc::clone(&self.guard),
        );
        self.session_id = uuid::Uuid::new_v4();
        info!(session = %self.session_id, "mcp: new saga session");
        Ok(())
    }

    /// Porta la FSM in `ExecutingTool(tool_id)` (Idle→Planning→ExecutingTool).
    /// Stati terminali/incompatibili → reset della saga e riprova.
    fn ensure_authorized(&mut self, tool_id: &str) -> KernelResult<()> {
        loop {
            match self.kernel.state().clone() {
                AgentState::Idle => {
                    self.kernel.begin_planning()?;
                }
                AgentState::Planning | AgentState::Verifying => {
                    self.kernel.begin_tool(tool_id)?;
                    return Ok(());
                }
                AgentState::ExecutingTool(current) if current == tool_id => return Ok(()),
                _ => self.reset_saga()?,
            }
        }
    }

    fn kernel_tool_id(mcp_name: &str) -> Option<&'static str> {
        match mcp_name {
            TOOL_FS_WRITE => Some(KERNEL_FS_WRITE),
            TOOL_MOCK_PAY => Some(KERNEL_MOCK_PAY),
            _ => None,
        }
    }

    fn text_result(text: String, is_error: bool) -> Value {
        json!({"content":[{"type":"text","text":text}],"isError":is_error})
    }

    fn ok_response(id: Value, result: Value) -> String {
        json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()
    }

    fn error_response(id: Value, code: i64, message: String) -> String {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}).to_string()
    }

    fn initialize_result() -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
        })
    }

    fn tools_list() -> Value {
        json!([
            {
                "name": TOOL_FS_WRITE,
                "description": "Write a file inside the sandboxed workspace (Step-0 security enforced, Saga rollback on failure). Compensates by deleting the file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Destination path inside the workspace"},
                        "content": {"type": "string", "description": "File content"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": TOOL_MOCK_PAY,
                "description": "Simulated payment (CHARGED). Compensates with REFUND on rollback.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payment_id": {"type": "string"},
                        "amount": {"type": "number"}
                    }
                }
            },
            {
                "name": TOOL_STATUS,
                "description": "Read-only kernel status: FSM state, saga session id and WAL actions.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": TOOL_GATEWAY,
                "description": "Universal protected gateway: proxy an external agent intent (tool_name + parameters, optional session_id) through Step-0 security, WAL tracking and automatic LIFO rollback. Use it to route arbitrary tool calls through SagaShield guardrails.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Target tool: fs_write / fs.write, mock_pay / mock.pay"},
                        "parameters": {"type": "object", "description": "Tool arguments (e.g. {\"path\": ..., \"content\": ...})"},
                        "session_id": {"type": "string", "description": "Optional saga UUID to join; a fresh one is used when omitted"},
                        "idempotency_key": {"type": "string", "description": "Optional anti-retry key: repeat calls with the same key return the cached output without re-executing"}
                    },
                    "required": ["tool_name", "parameters"]
                }
            },
            {
                "name": TOOL_REPLAY,
                "description": "Deterministic dry-run replay of a past saga from the WAL: timeline, FSM validation, compensations. No side effects.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Saga UUID to replay"}
                    },
                    "required": ["session_id"]
                }
            },
            {
                "name": TOOL_AUDIT,
                "description": "Export a session as OpenTelemetry JSON (resourceSpans) for Datadog, Honeycomb or Jaeger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Saga UUID to export"},
                        "format": {"type": "string", "description": "Must be otel_json"}
                    },
                    "required": ["session_id", "format"]
                }
            },
            {
                "name": TOOL_DLQ,
                "description": "List UNRESOLVED dead-letter entries (failed compensations awaiting SRE review). Read-only.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": TOOL_APPROVE,
                "description": "Approve a pending irreversible action with its approval token (human-in-the-loop).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "token": {"type": "string", "description": "Approval token from the ApprovalRequired error"}
                    },
                    "required": ["session_id", "token"]
                }
            },
            {
                "name": TOOL_REJECT,
                "description": "Reject a pending irreversible action (compensates prior steps) with an optional reason.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "token": {"type": "string"},
                        "reason": {"type": "string"}
                    },
                    "required": ["session_id", "token"]
                }
            },
            {
                "name": TOOL_PRUNE,
                "description": "Delete terminal saga history older than N days (UNRESOLVED DLQ entries are never touched), then vacuum.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "older_than_days": {"type": "number", "description": "Age threshold in days"}
                    },
                    "required": ["older_than_days"]
                }
            }
        ])
    }

    /// Stato kernel come blocco di testo (nessuna mutazione FSM/WAL).
    fn status_result(&self) -> Value {
        let session_str = self.session_id.to_string();
        let actions: Vec<Value> = self
            .wal
            .get_actions(&session_str)
            .unwrap_or_default()
            .iter()
            .map(|a| json!({"seq": a.step_seq, "tool": a.tool_id, "status": a.status.as_str()}))
            .collect();
        let text = serde_json::to_string_pretty(&json!({
            "state": self.kernel.state().to_string(),
            "session_id": session_str,
            "actions": actions,
        }))
        .unwrap_or_else(|_| "{}".to_owned());
        Self::text_result(text, false)
    }

    /// Tool compensati in una saga (per il report di rollback).
    fn compensated_list_for(&self, session: &uuid::Uuid) -> Vec<String> {
        self.wal
            .get_actions(&session.to_string())
            .unwrap_or_default()
            .iter()
            .filter(|a| a.status == ActionStatus::Compensated)
            .map(|a| a.tool_id.clone())
            .collect()
    }

    /// Esegue un `tools/call` già validato. Non lancia mai panic né errori
    /// di protocollo: ogni fallimento diventa `{isError: true}`.
    async fn call_tool(&mut self, name: &str, args: Value) -> Value {
        if name == TOOL_STATUS {
            return self.status_result();
        }
        if name == TOOL_GATEWAY {
            return self.call_gateway(args).await;
        }
        if name == TOOL_REPLAY || name == TOOL_AUDIT || name == TOOL_DLQ {
            return self.call_native(name, &args);
        }
        if name == TOOL_APPROVE || name == TOOL_REJECT || name == TOOL_PRUNE {
            return self.call_mutating(name, &args).await;
        }
        let tool_id = match Self::kernel_tool_id(name) {
            Some(id) => id,
            None => {
                return Self::text_result(format!("unknown tool '{name}'"), true);
            }
        };
        let session = self.session_id;
        self.execute_protected(session, name, tool_id, args, None)
            .await
    }

    /// Gateway universale: valida l'intento esterno e lo instrada con le
    /// stesse garanzie dei tool diretti (Step-0 → WAL → rollback LIFO).
    async fn call_gateway(&mut self, args: Value) -> Value {
        let tool_name = args.get("tool_name").and_then(Value::as_str).unwrap_or("");
        // Accetta `fs_write`, `fs.write` e `fs-write` indifferentemente.
        let normalized = tool_name.replace(['_', '-'], ".").to_lowercase();
        let tool_id = match normalized.as_str() {
            "fs.write" => KERNEL_FS_WRITE,
            "mock.pay" => KERNEL_MOCK_PAY,
            "kernel.status" => return self.status_result(),
            _ => {
                return Self::text_result(
                    format!(
                        "Gateway: unknown tool_name '{tool_name}' \
                         (try fs_write, mock_pay)"
                    ),
                    true,
                );
            }
        };
        let params = args.get("parameters").cloned().unwrap_or(json!({}));
        let session = match args.get("session_id") {
            None | Some(Value::Null) => self.session_id,
            Some(Value::String(s)) => match uuid::Uuid::parse_str(s) {
                Ok(u) => u,
                Err(_) => {
                    return Self::text_result(
                        format!("Gateway: invalid session_id '{s}' (must be UUID)"),
                        true,
                    );
                }
            },
            _ => {
                return Self::text_result(
                    "Gateway: session_id must be a UUID string".to_owned(),
                    true,
                );
            }
        };
        let display = format!("agent_kernel_exec({tool_name})");
        let idempotency_key = args
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.execute_protected(session, &display, tool_id, params, idempotency_key)
            .await
    }

    /// Replay/audit/dlq nativi: nessuna mutazione FSM/WAL, solo lettura.
    fn call_native(&self, name: &str, args: &Value) -> Value {
        // TOOL_DLQ non richiede sessione: ispezione globale SRE.
        if name == TOOL_DLQ {
            let entries = self.wal.get_unresolved_dlq().unwrap_or_default();
            let text = serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_owned());
            return Self::text_result(text, false);
        }
        let sid_str = args.get("session_id").and_then(Value::as_str).unwrap_or("");
        let session_id = match uuid::Uuid::parse_str(sid_str) {
            Ok(u) => u,
            Err(_) => {
                return Self::text_result(
                    format!("{name}: invalid session_id '{sid_str}' (must be UUID)"),
                    true,
                );
            }
        };
        if name == TOOL_REPLAY {
            return match crate::replay::SessionReplay::replay_session(&self.wal, &session_id) {
                Ok(timeline) => {
                    let text =
                        serde_json::to_string_pretty(&timeline).unwrap_or_else(|_| "{}".to_owned());
                    Self::text_result(text, false)
                }
                Err(e) => Self::text_result(format!("Replay failed: {e}"), true),
            };
        }
        // TOOL_AUDIT
        if name == TOOL_AUDIT {
            match args.get("format").and_then(Value::as_str) {
                Some("otel_json") => {}
                other => {
                    return Self::text_result(
                        format!("{name}: unsupported format {other:?} (use otel_json)"),
                        true,
                    );
                }
            }
            return match crate::audit::AuditExporter::export_session_otel_json(
                &self.wal,
                &session_id,
            ) {
                Ok(doc) => Self::text_result(doc, false),
                Err(e) => Self::text_result(format!("Audit export failed: {e}"), true),
            };
        }
        // TOOL_DLQ è gestito in testa (nessuna sessione richiesta).
        Self::text_result(format!("unknown native tool '{name}'"), true)
    }

    /// Tool con mutazione kernel: approve / reject / prune (serve `&mut`).
    async fn call_mutating(&mut self, name: &str, args: &Value) -> Value {
        if name == TOOL_PRUNE {
            let days = match args.get("older_than_days").and_then(Value::as_u64) {
                Some(d) => match u32::try_from(d) {
                    Ok(v) => v,
                    Err(_) => {
                        return Self::text_result(
                            format!("{name}: older_than_days out of range: {d}"),
                            true,
                        );
                    }
                },
                None => {
                    return Self::text_result(
                        format!("{name}: missing numeric older_than_days"),
                        true,
                    );
                }
            };
            return match self.wal.prune_history(days) {
                Ok(report) => match self.wal.vacuum() {
                    Ok(()) => Self::text_result(
                        format!(
                            "Pruned {} sessions / {} actions older than {days} days; vacuum done. UNRESOLVED DLQ preserved.",
                            report.sessions_deleted, report.actions_deleted
                        ),
                        false,
                    ),
                    Err(e) => Self::text_result(format!("Vacuum failed: {e}"), true),
                },
                Err(e) => Self::text_result(format!("Prune failed: {e}"), true),
            };
        }
        let sid_str = args.get("session_id").and_then(Value::as_str).unwrap_or("");
        let session_id = match uuid::Uuid::parse_str(sid_str) {
            Ok(u) => u,
            Err(_) => {
                return Self::text_result(
                    format!("{name}: invalid session_id '{sid_str}' (must be UUID)"),
                    true,
                );
            }
        };
        let token = args.get("token").and_then(Value::as_str).unwrap_or("");
        if name == TOOL_APPROVE {
            return match self.kernel.approve_action(&session_id, token).await {
                Ok(output) => {
                    Self::text_result(format!("Approved and executed: {}", output.data), false)
                }
                Err(e) => Self::text_result(format!("Approve failed: {e}"), true),
            };
        }
        // TOOL_REJECT
        let reason = args
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("rejected by operator");
        match self.kernel.reject_action(&session_id, token, reason).await {
            Ok(()) => Self::text_result(
                format!("Rejected ({reason}); prior steps compensated."),
                false,
            ),
            Err(e) => Self::text_result(format!("Reject failed: {e}"), true),
        }
    }

    /// Autorizza, esegue e mappa il risultato in un blocco di testo MCP.
    async fn execute_protected(
        &mut self,
        session: uuid::Uuid,
        label: &str,
        tool_id: &str,
        args: Value,
        idempotency_key: Option<String>,
    ) -> Value {
        if let Err(e) = self.ensure_authorized(tool_id) {
            warn!(tool = %label, error = %e, "mcp: cannot authorize tool");
            return Self::text_result(format!("Kernel error before execution: {e}"), true);
        }
        match self
            .kernel
            .execute_tool(&session, tool_id, args, idempotency_key)
            .await
        {
            Ok(output) => Self::text_result(format!("{label} OK: {}", output.data), false),
            Err(KernelError::SecurityViolation(detail)) => Self::text_result(
                format!(
                    "Security violation blocked at Step 0: {detail}. \
                     No state was mutated, nothing was written."
                ),
                true,
            ),
            Err(e) => {
                let detail = e.to_string();
                let text = if detail.contains("rollback report") {
                    format!("Errore rilevato. Rollback parziale: {detail}")
                } else {
                    let compensated = self.compensated_list_for(&session).join(", ");
                    format!(
                        "Errore rilevato. Rollback automatico completato con successo: \
                         [{compensated}]. Dettaglio: {detail}"
                    )
                };
                Self::text_result(text, true)
            }
        }
    }

    /// Gestisce una riga JSON-RPC. Ritorna `None` per notifiche/invalidi
    /// senza id (nessuna risposta, come da spec).
    pub async fn handle_message(&mut self, line: &str) -> Option<String> {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                return Some(Self::error_response(
                    Value::Null,
                    -32700,
                    "Parse error".to_owned(),
                ));
            }
        };
        if req.is_array() {
            return Some(Self::error_response(
                Value::Null,
                -32600,
                "Batch requests not supported".to_owned(),
            ));
        }
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let has_id = !id.is_null();

        match method {
            "initialize" => {
                if !has_id {
                    return None;
                }
                info!("mcp: initialize handshake");
                Some(Self::ok_response(id, Self::initialize_result()))
            }
            m if m.starts_with("notifications/") => None,
            "tools/list" => {
                if !has_id {
                    return None;
                }
                Some(Self::ok_response(id, json!({"tools": Self::tools_list()})))
            }
            "tools/call" => {
                if !has_id {
                    return None;
                }
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                if name != TOOL_STATUS
                    && name != TOOL_GATEWAY
                    && name != TOOL_REPLAY
                    && name != TOOL_AUDIT
                    && name != TOOL_DLQ
                    && name != TOOL_APPROVE
                    && name != TOOL_REJECT
                    && name != TOOL_PRUNE
                    && Self::kernel_tool_id(name).is_none()
                {
                    return Some(Self::error_response(
                        id,
                        -32602,
                        format!("unknown tool '{name}'"),
                    ));
                }
                Some(Self::ok_response(id, self.call_tool(name, args).await))
            }
            "" => {
                if has_id {
                    Some(Self::error_response(
                        id,
                        -32600,
                        "Invalid Request: missing method".to_owned(),
                    ))
                } else {
                    None
                }
            }
            other => {
                if has_id {
                    warn!(method = %other, "mcp: method not found");
                    Some(Self::error_response(
                        id,
                        -32601,
                        format!("Method not found: {other}"),
                    ))
                } else {
                    None
                }
            }
        }
    }

    /// Loop stdio: una richiesta JSON-RPC per riga su stdin, risposte su stdout.
    /// I log vanno su stderr (stdout è protocollo puro).
    pub async fn serve_stdio(&mut self) -> KernelResult<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut stdout = tokio::io::stdout();
        info!("{SERVER_NAME} listening on stdio");
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(resp) = self.handle_message(&line).await {
                stdout.write_all(resp.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }
        Ok(())
    }
}
