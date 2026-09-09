//! SagaShield — ACID transactional Saga runtime, Step-0 security guardrail,
//! and MCP server for autonomous AI agents.
//!
//! Every tool call runs inside a saga: it is authorized by a deterministic
//! [`StateMachine`], logged to a SQLite write-ahead log ([`Wal`]), executed
//! through a [`TransactionalTool`], and — on failure — compensated in reverse
//! order (Saga rollback). A [`SecurityGuard`] screens requests *before* the
//! FSM check, the WAL write, or any side effect.
//!
//! ## Architecture
//!
//! - [`AgentKernel`] — single entry point: FSM + WAL + [`ToolRegistry`] +
//!   optional security guard, with automatic LIFO rollback.
//! - [`Wal`] — `sessions`/`actions` tables, idempotency lookups, dangling
//!   session recovery, OTel-ready tracing spans.
//! - [`SessionReplay`] — deterministic dry-run replay of a past saga with
//!   formal FSM re-validation (no side effects).
//! - [`AuditExporter`] — session export as OpenTelemetry `resourceSpans` JSON.
//! - [`McpServer`] — JSON-RPC 2.0 stdio server (`sagashield-mcp` binary).
//!
//! ## Quickstart
//!
//! ```rust
//! use std::sync::Arc;
//! use sagashield::{
//!     AgentKernel, KernelError, ToolContext, ToolOutput, ToolRegistry,
//!     TransactionalTool, Wal,
//! };
//! use serde_json::{Value, json};
//!
//! struct GreetTool;
//!
//! #[async_trait::async_trait]
//! impl TransactionalTool for GreetTool {
//!     fn id(&self) -> &'static str { "greet" }
//!
//!     async fn execute(
//!         &self,
//!         _ctx: &ToolContext,
//!         args: Value,
//!     ) -> Result<ToolOutput, KernelError> {
//!         let name = args.get("name").and_then(Value::as_str).unwrap_or("world");
//!         Ok(ToolOutput::new(json!({ "greeting": format!("hello {name}") })))
//!     }
//!
//!     async fn compensate(
//!         &self,
//!         _ctx: &ToolContext,
//!         _args: Value,
//!         _output: ToolOutput,
//!     ) -> Result<(), KernelError> {
//!         Ok(())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let wal = Arc::new(Wal::open_in_memory()?);
//!     let registry = ToolRegistry::new();
//!     registry.register(Arc::new(GreetTool))?;
//!
//!     let mut kernel = AgentKernel::new(wal, registry);
//!     let session = uuid::Uuid::new_v4();
//!     kernel.begin_planning()?;
//!     kernel.begin_tool("greet")?;
//!     let out = kernel.execute_tool(&session, "greet", json!({ "name": "ada" }), None).await?;
//!     assert!(out.data["greeting"] == "hello ada");
//!     Ok(())
//! }
//! ```

pub mod audit;
pub mod dispatcher;
pub mod error;
pub mod fsm;
pub mod knowledge;
pub mod mcp;
pub mod memory;
#[cfg(feature = "python")]
pub mod python;
pub mod replay;
pub mod router;
pub mod security;
pub mod tools;
pub mod traits;
pub mod types;
pub mod wal;

pub use audit::AuditExporter;
pub use dispatcher::{AgentKernel, ToolRegistry};
pub use error::{KernelError, KernelResult};
pub use fsm::{AgentEvent, AgentState, StateMachine};
pub use knowledge::{
    Citation, GroundedHit, KnowledgeFabric, KnowledgeRecord, KnowledgeRetrieveTool, NewRecordInput,
    RetrievalPolicy,
};
pub use mcp::McpServer;
pub use memory::{
    MemoryHit, MemoryKind, MemoryRecallTool, MemoryRecord, MemoryScope, MemoryStoreTool,
    MemoryVault, NewMemoryInput, RecallPolicy,
};
pub use replay::{ReplayStep, ReplayTimeline, SessionReplay};
pub use router::{
    BackendCatalog, CloudBackend, InferenceRouter, LocalBackend, Quant, RoutePlan, RouterPlanTool,
    SloPolicy, TaskSpec, estimate_vram_gb,
};
pub use security::{SecurityGuard, SecurityPolicy};
pub use traits::TransactionalTool;
pub use types::{ActionStatus, DlqEntry, PersistedAction, PruneReport, ToolContext, ToolOutput};
pub use wal::Wal;

/// Modulo nativo Python `_core` (solo con `--features python`, maturin).
#[cfg(feature = "python")]
#[pyo3::pymodule]
fn _core(m: &pyo3::Bound<pyo3::types::PyModule>) -> pyo3::PyResult<()> {
    python::register_module(m)
}
