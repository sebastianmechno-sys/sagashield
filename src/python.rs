//! Python bindings via PyO3 (feature `python`, modulo nativo `_core`).
//!
//! Protocollo JSON-stringhe attraverso il confine GIL: i callable Python
//! ricevono `(ctx_json, args_json)` e restituiscono output-data come stringa
//! JSON. Le eccezioni Python diventano [`KernelError::ToolExecution`] e
//! innescano il rollback LIFO come qualsiasi altro fallimento.
//!
//! Nota async: il kernel gira su un runtime Tokio dedicato dentro
//! [`PySagaKernel`]; i callback Python sono invocati con `Python::with_gil`
//! in sezioni sincrone (mai attraverso `.await`). Non richiamare il kernel
//! dall'interno di un tool callback (deadlock sul runtime).
//!
//! Nota lint: pyo3 0.22 precede l'edition 2024, le sue macro generano
//! `unsafe_op_in_unsafe_fn`/`unexpected_cfgs`/`useless_conversion` innocui —
//! silenziati qui con commento, non nel resto del crate.
#![allow(unsafe_op_in_unsafe_fn, unexpected_cfgs, clippy::useless_conversion)]

use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::Value;

use crate::dispatcher::{AgentKernel, ToolRegistry};
use crate::error::{KernelError, KernelResult};
use crate::replay::SessionReplay;
use crate::security::{SecurityGuard, SecurityPolicy};
use crate::traits::TransactionalTool;
use crate::types::{ToolContext, ToolOutput};
use crate::wal::Wal;

pyo3::create_exception!(_core, SecurityViolationError, pyo3::exceptions::PyException);

/// Converte un errore kernel in eccezione Python tipizzata.
fn kernel_err_to_py(e: KernelError) -> PyErr {
    match e {
        KernelError::SecurityViolation(detail) => SecurityViolationError::new_err(detail),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

/// Policy di sandbox costruibile da Python.
#[pyclass]
pub struct PySecurityPolicy {
    inner: Arc<SecurityPolicy>,
}

#[pymethods]
impl PySecurityPolicy {
    /// Crea una policy.
    ///
    /// `allowed_roots`: directory consentite; `blocked_patterns`: default
    /// `[".env", ".git", "id_rsa", "id_ed25519", "credentials"]`;
    /// `allowed_domains`: default `[]` (tutto bloccato).
    #[new]
    #[pyo3(signature = (allowed_roots, blocked_patterns=None, allowed_domains=None))]
    fn new(
        allowed_roots: Vec<String>,
        blocked_patterns: Option<Vec<String>>,
        allowed_domains: Option<Vec<String>>,
    ) -> Self {
        Self {
            inner: Arc::new(SecurityPolicy::new(
                allowed_roots
                    .into_iter()
                    .map(std::path::PathBuf::from)
                    .collect(),
                blocked_patterns.unwrap_or_else(|| {
                    vec![
                        ".env".to_owned(),
                        ".git".to_owned(),
                        "id_rsa".to_owned(),
                        "id_ed25519".to_owned(),
                        "credentials".to_owned(),
                    ]
                }),
                allowed_domains.unwrap_or_default(),
            )),
        }
    }
}

/// Tool Rust che delega a callable Python `(ctx_json, args_json) -> str`.
struct PyTool {
    /// Nome stabile (leaked una volta per registrazione).
    name: &'static str,
    execute_cb: PyObject,
    compensate_cb: Option<PyObject>,
}

impl PyTool {
    fn ctx_json(ctx: &ToolContext) -> KernelResult<String> {
        serde_json::to_string(&serde_json::json!({
            "session_id": ctx.session_id,
            "step_seq": ctx.step_seq,
            "tool_id": ctx.tool_id,
            "idempotency_key": ctx.idempotency_key,
        }))
        .map_err(KernelError::from)
    }

    fn call_str(
        cb: &PyObject,
        payload: (String, String, Option<String>),
    ) -> Result<String, KernelError> {
        let (ctx_json, args_json, output_json) = payload;
        Python::with_gil(|py| {
            let result = match output_json {
                Some(out) => cb.call1(py, (ctx_json, args_json, out)),
                None => cb.call1(py, (ctx_json, args_json)),
            }
            .map_err(|e| KernelError::ToolExecution {
                tool_id: "<python>".to_owned(),
                message: format!("python callback raised: {e}"),
            })?;
            result
                .extract::<String>(py)
                .map_err(|e| KernelError::ToolExecution {
                    tool_id: "<python>".to_owned(),
                    message: format!("callback must return a JSON string: {e}"),
                })
        })
    }
}

#[async_trait::async_trait]
impl TransactionalTool for PyTool {
    fn id(&self) -> &'static str {
        self.name
    }

    async fn execute(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput, KernelError> {
        let args_json = serde_json::to_string(&args).map_err(KernelError::from)?;
        let out_json = Self::call_str(&self.execute_cb, (Self::ctx_json(ctx)?, args_json, None))?;
        let data: Value =
            serde_json::from_str(&out_json).map_err(|e| KernelError::ToolExecution {
                tool_id: self.name.to_owned(),
                message: format!("execute must return JSON: {e}"),
            })?;
        Ok(ToolOutput::new(data))
    }

    async fn compensate(
        &self,
        ctx: &ToolContext,
        args: Value,
        output: ToolOutput,
    ) -> Result<(), KernelError> {
        let Some(cb) = self.compensate_cb.as_ref() else {
            return Ok(());
        };
        let args_json = serde_json::to_string(&args).map_err(KernelError::from)?;
        let output_json = serde_json::to_string(&output.data).map_err(KernelError::from)?;
        Self::call_str(cb, (Self::ctx_json(ctx)?, args_json, Some(output_json)))?;
        Ok(())
    }
}

/// Kernel SagaShield pilotabile da Python (thread-safe via `Mutex` interno).
#[pyclass]
pub struct PySagaKernel {
    rt: tokio::runtime::Runtime,
    kernel: Mutex<AgentKernel>,
    wal: Arc<Wal>,
    session_id: Mutex<uuid::Uuid>,
}

impl PySagaKernel {
    /// Blocca il kernel interno (errore se avvelenato). Helper non esposto.
    fn lock_kernel(&self) -> PyResult<std::sync::MutexGuard<'_, AgentKernel>> {
        self.kernel
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("kernel lock poisoned: {e}")))
    }
}

#[pymethods]
impl PySagaKernel {
    /// Crea il kernel. `db_path=None` ⇒ WAL in-memory.
    #[new]
    #[pyo3(signature = (db_path=None, policy=None))]
    fn new(db_path: Option<String>, policy: Option<Py<PySecurityPolicy>>) -> PyResult<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("tokio runtime: {e}")))?;
        let wal = Arc::new(
            match db_path {
                Some(p) => Wal::open(p),
                None => Wal::open_in_memory(),
            }
            .map_err(kernel_err_to_py)?,
        );
        let registry = ToolRegistry::new();
        let kernel = match policy {
            Some(p) => {
                let guard: Arc<dyn SecurityGuard> =
                    Python::with_gil(|py| Arc::clone(&p.bind(py).borrow().inner));
                AgentKernel::with_security_guard(Arc::clone(&wal), registry, guard)
            }
            None => AgentKernel::new(Arc::clone(&wal), registry),
        };
        Ok(Self {
            rt,
            kernel: Mutex::new(kernel),
            wal,
            session_id: Mutex::new(uuid::Uuid::new_v4()),
        })
    }

    /// Nuova saga: ruota il session id e lo ritorna.
    fn new_session(&self) -> PyResult<String> {
        let mut guard = self
            .session_id
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("session lock poisoned: {e}")))?;
        *guard = uuid::Uuid::new_v4();
        Ok(guard.to_string())
    }

    /// Session id corrente (per replay/audit della saga attiva).
    fn session_id(&self) -> PyResult<String> {
        Ok(self
            .session_id
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("session lock poisoned: {e}")))?
            .to_string())
    }

    /// Stato FSM corrente (`Idle`, `Planning`, ...).
    fn state(&self) -> PyResult<String> {
        Ok(self.lock_kernel()?.state().to_string())
    }

    /// `Idle` → `Planning`.
    fn begin_planning(&self) -> PyResult<String> {
        let next = self
            .lock_kernel()?
            .begin_planning()
            .map_err(kernel_err_to_py)?;
        Ok(next.to_string())
    }

    /// `Planning`/`Verifying` → `ExecutingTool(tool_name)`.
    fn begin_tool(&self, tool_name: &str) -> PyResult<String> {
        let next = self
            .lock_kernel()?
            .begin_tool(tool_name)
            .map_err(kernel_err_to_py)?;
        Ok(next.to_string())
    }

    /// `Verifying` → `Completed`.
    fn complete(&self) -> PyResult<String> {
        let next = self.lock_kernel()?.complete().map_err(kernel_err_to_py)?;
        Ok(next.to_string())
    }

    /// Registra un tool Python. `py_execute(ctx_json, args_json) -> str`;
    /// `py_compensate(ctx_json, args_json, output_json) -> None` opzionale.
    #[pyo3(signature = (name, py_execute, py_compensate=None))]
    fn register_tool(
        &self,
        name: String,
        py_execute: PyObject,
        py_compensate: Option<PyObject>,
    ) -> PyResult<()> {
        // Leaked una volta per registrazione: costo fisso, mai in hot path.
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        let tool = PyTool {
            name: leaked,
            execute_cb: py_execute,
            compensate_cb: py_compensate,
        };
        self.lock_kernel()?
            .registry()
            .register(Arc::new(tool))
            .map_err(kernel_err_to_py)?;
        Ok(())
    }

    /// Esegue un tool (Step-0 → FSM → WAL → rollback). Ritorna output-data JSON.
    #[pyo3(signature = (tool_name, params_json, idempotency_key=None))]
    fn execute_tool(
        &self,
        tool_name: &str,
        params_json: &str,
        idempotency_key: Option<String>,
    ) -> PyResult<String> {
        let params: Value = serde_json::from_str(params_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid params_json: {e}")))?;
        let sid = *self
            .session_id
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("session lock poisoned: {e}")))?;
        let mut kernel = self.lock_kernel()?;
        let output = self
            .rt
            .block_on(kernel.execute_tool(&sid, tool_name, params, idempotency_key))
            .map_err(kernel_err_to_py)?;
        serde_json::to_string(&output.data)
            .map_err(|e| PyRuntimeError::new_err(format!("output not serializable: {e}")))
    }

    /// Replay dry-run di una saga passata (timeline JSON).
    fn replay_session(&self, session_id: &str) -> PyResult<String> {
        let sid = uuid::Uuid::parse_str(session_id)
            .map_err(|_| PyRuntimeError::new_err(format!("invalid session_id '{session_id}'")))?;
        let timeline = SessionReplay::replay_session(&self.wal, &sid).map_err(kernel_err_to_py)?;
        serde_json::to_string_pretty(&timeline)
            .map_err(|e| PyRuntimeError::new_err(format!("timeline not serializable: {e}")))
    }

    /// Export audit OTel (`resourceSpans` JSON).
    fn export_audit_otel(&self, session_id: &str) -> PyResult<String> {
        let sid = uuid::Uuid::parse_str(session_id)
            .map_err(|_| PyRuntimeError::new_err(format!("invalid session_id '{session_id}'")))?;
        crate::audit::AuditExporter::export_session_otel_json(&self.wal, &sid)
            .map_err(kernel_err_to_py)
    }
}

/// Azioni WAL grezze (debug): quante righe per sessione.
#[pyfunction]
fn _debug_info() -> PyResult<String> {
    Ok(format!("sagashield {}", env!("CARGO_PKG_VERSION")))
}

/// Costruisce il modulo nativo `_core` (registrato da `lib.rs`).
pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySagaKernel>()?;
    m.add_class::<PySecurityPolicy>()?;
    m.add(
        "SecurityViolationError",
        m.py().get_type_bound::<SecurityViolationError>(),
    )?;
    m.add_function(wrap_pyfunction!(_debug_info, m)?)?;
    Ok(())
}
