//! Dispatcher & punto di ingresso unificato — Fase 3.
//!
//! [`AgentKernel`] unisce FSM Guardrail + WAL + Registry:
//! ogni `execute_tool` è autorizzato dalla FSM, loggato sul WAL,
//! e su errore innesca automaticamente il rollback LIFO.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde_json::Value;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::{KernelError, KernelResult};
use crate::fsm::{AgentEvent, AgentState, StateMachine};
use crate::security::SecurityGuard;
use crate::traits::TransactionalTool;
use crate::types::{ActionStatus, ToolContext, ToolOutput};
use crate::wal::Wal;

/// Registro concorrente dei tool (`tool_id → tool`).
///
/// Interno `RwLock` per registrazione/lettura da più thread/task.
pub struct ToolRegistry {
    inner: RwLock<HashMap<String, Arc<dyn TransactionalTool>>>,
}

impl ToolRegistry {
    /// Registro vuoto.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Registra (o sostituisce) un tool. Chiave = `tool.id()`.
    pub fn register(&self, tool: Arc<dyn TransactionalTool>) -> KernelResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| KernelError::Lock(e.to_string()))?;
        guard.insert(tool.id().to_owned(), tool);
        Ok(())
    }

    /// Lookup per nome.
    pub fn get(&self, tool_name: &str) -> Option<Arc<dyn TransactionalTool>> {
        self.inner.read().ok()?.get(tool_name).cloned()
    }

    /// Snapshot per il rollback del WAL (evita di tenere il lock su `.await`).
    pub fn snapshot(&self) -> KernelResult<HashMap<String, Arc<dyn TransactionalTool>>> {
        let guard = self
            .inner
            .read()
            .map_err(|e| KernelError::Lock(e.to_string()))?;
        Ok(guard.clone())
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Punto di ingresso unificato: FSM + WAL + Registry + Security Guard.
pub struct AgentKernel {
    fsm: StateMachine,
    wal: Arc<Wal>,
    registry: ToolRegistry,
    security_guard: Option<Arc<dyn SecurityGuard>>,
}

impl AgentKernel {
    /// Crea il kernel (FSM parte da `Idle`, nessuna security guard).
    pub fn new(wal: Arc<Wal>, registry: ToolRegistry) -> Self {
        Self {
            fsm: StateMachine::new(),
            wal,
            registry,
            security_guard: None,
        }
    }

    /// Crea il kernel con security guard attiva (sandboxing Fase 4).
    pub fn with_security_guard(
        wal: Arc<Wal>,
        registry: ToolRegistry,
        guard: Arc<dyn SecurityGuard>,
    ) -> Self {
        Self {
            fsm: StateMachine::new(),
            wal,
            registry,
            security_guard: Some(guard),
        }
    }

    /// Installa/sostituisce la security guard su un kernel esistente.
    pub fn set_security_guard(&mut self, guard: Arc<dyn SecurityGuard>) {
        self.security_guard = Some(guard);
    }

    /// Stato FSM corrente.
    pub fn state(&self) -> &AgentState {
        self.fsm.state()
    }

    /// Accesso al registry (es. per la crash recovery).
    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// WAL condiviso (es. per replay/audit/export esterni al kernel).
    pub fn wal(&self) -> &Arc<Wal> {
        &self.wal
    }

    /// `Idle` → `Planning` (inizio sessione logica).
    pub fn begin_planning(&mut self) -> KernelResult<AgentState> {
        self.fsm.transition(AgentEvent::StartPlanning)
    }

    /// `Planning`/`Verifying` → `ExecutingTool(tool_name)` (autorizza quel tool).
    pub fn begin_tool(&mut self, tool_name: &str) -> KernelResult<AgentState> {
        self.fsm.transition(AgentEvent::StartExecution {
            tool_name: tool_name.to_owned(),
        })
    }

    /// `Verifying` → `Completed` (validazione superata, saga conclusa).
    pub fn complete(&mut self) -> KernelResult<AgentState> {
        self.fsm.transition(AgentEvent::ValidationPassed)
    }

    /// Crash recovery / blackout: compensa le sessioni orfane.
    ///
    /// Scansiona il WAL cercando sessioni con azioni `PENDING` o `COMMITTED`
    /// mai finalizzate (crash senza graceful shutdown) ed esegue il rollback
    /// automatico. Non tocca la FSM locale (operazione cross-sessione sul DB).
    /// Ritorna il numero di sessioni recuperate.
    pub async fn recover_dangling_sessions(
        &self,
        registry: &ToolRegistry,
    ) -> Result<usize, KernelError> {
        let snapshot = registry.snapshot()?;
        Ok(self.wal.recover_dangling(&snapshot).await?.len())
    }

    /// Prossima sequenza per la sessione (max esistente + 1, 0 se vuota).
    fn next_seq(&self, session_str: &str) -> KernelResult<u64> {
        let actions = self.wal.get_actions(session_str)?;
        let mut max: Option<u64> = None;
        for a in &actions {
            max = Some(max.map_or(a.step_seq, |m| m.max(a.step_seq)));
        }
        Ok(max.map_or(0, |m| m.saturating_add(1)))
    }

    /// Step 0: verifica generica dei params contro la security guard.
    ///
    /// Controlli applicati:
    ///
    /// - `path` → `check_path_access` (anti traversal + file bloccati).
    /// - `url` / `domain` / `endpoint` → `check_network_access` (whitelist).
    ///
    /// Ritorna l'errore specifico del guard (il chiamante lo wrappa in
    /// `SecurityViolation` senza effetti collaterali).
    fn security_check(guard: &Arc<dyn SecurityGuard>, params: &Value) -> KernelResult<()> {
        if let Some(path_str) = params.get("path").and_then(Value::as_str) {
            guard.check_path_access(std::path::Path::new(path_str))?;
        }
        for key in ["url", "domain", "endpoint"] {
            if let Some(net) = params.get(key).and_then(Value::as_str) {
                guard.check_network_access(net)?;
            }
        }
        Ok(())
    }

    /// Esegue un tool con guardrail FSM + WAL + rollback automatico.
    ///
    /// 0. Security guard — se attiva, verifica `path`/`url` nei params PRIMA di
    ///    qualsiasi altra operazione (FSM inclusa). Se fallisce ritorna subito
    ///    `SecurityViolation` **senza toccare il DB e senza mutare la FSM**.
    /// 1. `can_execute_tool` — se no, errore immediato **senza toccare il DB**.
    ///
    /// 1b. Idempotenza — se `idempotency_key` è fornita ed esiste già
    /// un'azione `COMMITTED` con quella chiave nella sessione, ritorna
    /// l'output cachato senza rieseguire (short-circuit anti-retry).
    ///
    /// 2. Log WAL `PENDING` (con la chiave fornita, o deterministica).
    /// 3. `tool.execute()`.
    /// 4. SUCCESSO → WAL `COMMITTED` + FSM `ToolSucceeded` (→ `Verifying`).
    /// 5. ERRORE → WAL `FAILED` + FSM `ToolFailed` (→ `Compensating`),
    ///    `wal.rollback()` LIFO, FSM `CompensationCompleted` (→ `Failed`),
    ///    ritorna l'errore originale (o il report di rollback se parziale).
    ///
    /// Attributi OTel sullo span `agent.tool.execute`: `agent.session_id`,
    /// `agent.tool.name`, `agent.tool.idempotency_key`, `agent.fsm.state`,
    /// `agent.rollback.triggered`, `security.violation.type`.
    pub async fn execute_tool(
        &mut self,
        session_id: &Uuid,
        tool_name: &str,
        params: Value,
        idempotency_key: Option<String>,
    ) -> KernelResult<ToolOutput> {
        let session_str = session_id.to_string();
        let span = tracing::info_span!(
            "agent.tool.execute",
            "agent.session_id" = %session_str,
            "agent.tool.name" = %tool_name,
            "agent.tool.idempotency_key" = tracing::field::Empty,
            "agent.fsm.state" = %self.fsm.state().to_string(),
            "agent.rollback.triggered" = false,
            "security.violation.type" = tracing::field::Empty,
        );
        let _span_guard = span.enter();
        if let Some(key) = idempotency_key.as_deref() {
            span.record("agent.tool.idempotency_key", key);
        }

        // 0. Security PRIMA di tutto (difesa da prompt injection).
        if let Some(guard) = &self.security_guard
            && let Err(e) = Self::security_check(guard, &params)
        {
            span.record("security.violation.type", "step0_block");
            error!(tool = %tool_name, error = %e, "SECURITY BLOCK -> esecuzione negata");
            return Err(KernelError::SecurityViolation(e.to_string()));
        }

        // 1. Guardrail PRIMA di qualsiasi I/O sul DB.
        if !self.fsm.can_execute_tool(tool_name) {
            return Err(KernelError::InvalidStateTransition {
                current: self.fsm.state().to_string(),
                event: format!("Execute({tool_name})"),
            });
        }

        // Lookup tool PRIMA del WAL (nessuna riga orfana se il tool manca).
        let Some(tool) = self.registry.get(tool_name) else {
            return Err(KernelError::ToolNotFound(tool_name.to_owned()));
        };

        // 1c. Tool irreversibile → 2-Phase Commit: niente esecuzione,
        // solo PENDING_APPROVAL + attesa umana.
        if tool.is_irreversible() {
            let token = uuid::Uuid::new_v4().to_string();
            let seq = self.next_seq(&session_str)?;
            let mut ctx = ToolContext::new(session_str.clone(), seq, tool_name);
            if let Some(key) = idempotency_key {
                ctx.idempotency_key = key;
            }
            self.wal.log_pending_approval(&ctx, &params)?;
            self.fsm.transition(AgentEvent::RequireApproval {
                tool_name: tool_name.to_owned(),
                approval_token: token.clone(),
            })?;
            warn!(tool = %tool_name, "irreversible tool parked in AwaitingApproval");
            return Err(KernelError::ApprovalRequired {
                tool_name: tool_name.to_owned(),
                token,
            });
        }

        // 1b. Short-circuit idempotente: COMMITTED con stessa chiave → cache.
        if let Some(key) = idempotency_key.as_deref()
            && let Some(existing) = self.wal.find_by_idempotency_key(session_id, key)?
            && existing.status == ActionStatus::Committed
            && let Some(cached) = existing.output
        {
            info!(
                tool = %tool_name,
                key = %key,
                "Idempotent hit: skipped execution"
            );
            self.fsm.transition(AgentEvent::ToolSucceeded)?;
            return Ok(cached);
        }

        // 2. PENDING sul WAL (chiave chiamante o deterministica).
        let seq = self.next_seq(&session_str)?;
        let mut ctx = ToolContext::new(session_str.clone(), seq, tool_name);
        if let Some(key) = idempotency_key {
            ctx.idempotency_key = key;
        }
        let action_id = self.wal.log_action(&ctx, &params)?;

        self.run_logged_step(&session_str, &tool, &ctx, action_id, &params, &span)
            .await
    }

    /// Esegue uno step già loggato (passi 3-5): `execute`, poi `COMMITTED`
    /// + `Verifying` oppure `FAILED` + rollback LIFO + `Failed`.
    async fn run_logged_step(
        &mut self,
        session_str: &str,
        tool: &Arc<dyn TransactionalTool>,
        ctx: &ToolContext,
        action_id: i64,
        params: &Value,
        span: &tracing::Span,
    ) -> KernelResult<ToolOutput> {
        let tool_name = tool.id();
        let seq = ctx.step_seq;
        // 3. Esecuzione reale.
        match tool.execute(ctx, params.clone()).await {
            Ok(output) => {
                // 4. SUCCESSO.
                self.wal.mark_committed(action_id, &output)?;
                info!(tool = %tool_name, seq, "execute OK → COMMITTED");
                self.fsm.transition(AgentEvent::ToolSucceeded)?;
                Ok(output)
            }
            Err(original) => {
                // 5. ERRORE → rollback automatico.
                span.record("agent.rollback.triggered", true);
                error!(tool = %tool_name, seq, error = %original, "CRASH RILEVATO -> Avvio Rollback LIFO...");
                if let Err(e) = self.wal.mark_failed(action_id, &original.to_string()) {
                    error!(error = %e, "WAL mark_failed failed");
                }
                if let Err(e) = self.fsm.transition(AgentEvent::ToolFailed) {
                    warn!(error = %e, "FSM -> Compensating failed (continuo con rollback)");
                } else {
                    info!("FSM → Compensating: nuovi execute bloccati, solo compensate");
                }

                let registry_snapshot = self.registry.snapshot()?;
                let rollback_result = self.wal.rollback(session_str, &registry_snapshot).await;
                match &rollback_result {
                    Ok(()) => info!("Rollback LIFO completato: sistema in sicurezza"),
                    Err(e) => warn!(error = %e, "Rollback parziale!"),
                }

                if let Err(e) = self.fsm.transition(AgentEvent::CompensationCompleted) {
                    warn!(error = %e, "FSM -> Failed failed");
                } else {
                    info!("FSM → Failed (terminale)");
                }

                // Ritorna l'errore originale arricchito dal report di rollback.
                match rollback_result {
                    Ok(()) => Err(original),
                    Err(rbk) => Err(KernelError::ToolExecution {
                        tool_id: tool_name.to_owned(),
                        message: format!("{original} | rollback report: {rbk}"),
                    }),
                }
            }
        }
    }

    /// Approva un'azione irreversibile in `AwaitingApproval` (2-Phase Commit).
    ///
    /// Valida il token contro lo stato FSM, transita in `ExecutingTool`,
    /// esegue l'azione `PENDING_APPROVAL` e scrive `COMMITTED`. Token errato
    /// o stato diverso → `InvalidStateTransition`, nessun side-effect.
    pub async fn approve_action(
        &mut self,
        session_id: &Uuid,
        token: &str,
    ) -> KernelResult<ToolOutput> {
        let session_str = session_id.to_string();
        let tool_name = match self.fsm.state() {
            AgentState::AwaitingApproval {
                tool_name,
                approval_token,
            } if approval_token == token => tool_name.clone(),
            other => {
                return Err(KernelError::InvalidStateTransition {
                    current: other.to_string(),
                    event: "ApproveExecution".to_owned(),
                });
            }
        };
        let Some(tool) = self.registry.get(&tool_name) else {
            return Err(KernelError::ToolNotFound(tool_name));
        };
        let Some(pending) = self.wal.find_pending_approval(&session_str, &tool_name)? else {
            return Err(KernelError::InvalidStatus(format!(
                "pending approval row missing for '{tool_name}' (wal inconsistent)"
            )));
        };
        self.fsm.transition(AgentEvent::ApproveExecution {
            approval_token: token.to_owned(),
        })?;
        info!(tool = %tool_name, "operator approved irreversible action");
        let ctx = ToolContext {
            session_id: session_str.clone(),
            step_seq: pending.step_seq,
            tool_id: tool_name,
            idempotency_key: pending.idempotency_key,
        };
        let span = tracing::info_span!(
            "agent.tool.execute",
            "agent.session_id" = %session_str,
            "agent.tool.name" = %ctx.tool_id,
            "agent.tool.idempotency_key" = %ctx.idempotency_key,
            "agent.fsm.state" = %"ExecutingTool",
            "agent.rollback.triggered" = false,
            "security.violation.type" = tracing::field::Empty,
        );
        let _span_guard = span.enter();
        self.run_logged_step(&session_str, &tool, &ctx, pending.id, &pending.args, &span)
            .await
    }

    /// Rifiuta un'azione irreversibile in `AwaitingApproval`.
    ///
    /// Marca la riga `PENDING_APPROVAL` come `FAILED`, transita in `Failed`
    /// e compensa in LIFO le azioni precedenti. Token errato → nessun effetto.
    pub async fn reject_action(
        &mut self,
        session_id: &Uuid,
        token: &str,
        reason: &str,
    ) -> KernelResult<()> {
        let session_str = session_id.to_string();
        let tool_name = match self.fsm.state() {
            AgentState::AwaitingApproval {
                tool_name,
                approval_token,
            } if approval_token == token => tool_name.clone(),
            other => {
                return Err(KernelError::InvalidStateTransition {
                    current: other.to_string(),
                    event: "RejectExecution".to_owned(),
                });
            }
        };
        if let Some(pending) = self.wal.find_pending_approval(&session_str, &tool_name)? {
            self.wal
                .mark_failed(pending.id, &format!("rejected by operator: {reason}"))?;
        }
        self.fsm.transition(AgentEvent::RejectExecution {
            approval_token: token.to_owned(),
        })?;
        warn!(tool = %tool_name, reason = %reason, "operator rejected irreversible action");
        let snapshot = self.registry.snapshot()?;
        // La FSM è già terminale (Failed): il rollback pulisce il passato,
        // propagando l'eventuale report parziale (con DLQ registrata).
        self.wal.rollback(&session_str, &snapshot).await
    }
}
