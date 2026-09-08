//! FSM Guardrail — Fase 2.
//!
//! Macchina a stati deterministica che vincola il ciclo di vita dell'agente.
//! Tabella di transizione (default-deny, come da SPEC.md §3.4 adattata):
//!
//! | Da             | Evento                | A                  |
//! |----------------|-----------------------|--------------------|
//! | `Idle`         | `StartPlanning`       | `Planning`         |
//! | `Planning`     | `StartExecution(t)`   | `ExecutingTool(t)` |
//! | `ExecutingTool`| `ToolSucceeded`       | `Verifying`        |
//! | `ExecutingTool`| `ToolFailed`          | `Compensating`     |
//! | `Verifying`    | `ValidationPassed`    | `Completed`        |
//! | `Verifying`    | `ValidationFailed`    | `Compensating`     |
//! | `Verifying`    | `StartExecution(t)`   | `ExecutingTool(t)` |
//! | `Planning`/`ExecutingTool` | `RequireApproval(t)` | `AwaitingApproval(t)` |
//! | `AwaitingApproval` | `ApproveExecution`  | `ExecutingTool(t)` |
//! | `AwaitingApproval` | `RejectExecution`   | `Failed`           |
//! | `Compensating` | `CompensationCompleted`| `Failed`          |
//!
//! Tutto il resto → [`crate::error::KernelError::InvalidStateTransition`].
//! `Completed` e `Failed` sono terminali.

use std::fmt;

use crate::error::{KernelError, KernelResult};

/// Stato dell'agente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// Nessuna saga attiva.
    Idle,
    /// Pianificazione dei passi (solo tool read-only, Fase 3+).
    Planning,
    /// Esecuzione di un tool specifico (solo quel tool è autorizzato).
    ExecutingTool(String),
    /// Verifica post-azione.
    Verifying,
    /// Rollback Saga in corso (nessun `execute` ammesso, solo `compensate`).
    Compensating,
    /// Azione irreversibile in attesa di approvazione umana (2-Phase Commit).
    /// Il token è confrontato esattamente su approve/reject.
    AwaitingApproval {
        /// Tool in attesa di esecuzione.
        tool_name: String,
        /// Token di approvazione (UUID v4 generato dal kernel).
        approval_token: String,
    },
    /// Saga committata con successo. Terminale.
    Completed,
    /// Saga fallita (dopo compensazione). Terminale.
    Failed,
}

impl fmt::Display for AgentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Planning => write!(f, "Planning"),
            Self::ExecutingTool(name) => write!(f, "ExecutingTool({name})"),
            Self::Verifying => write!(f, "Verifying"),
            Self::Compensating => write!(f, "Compensating"),
            Self::AwaitingApproval { tool_name, .. } => {
                write!(f, "AwaitingApproval({tool_name})")
            }
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Evento che innesca una transizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    /// `Idle` → `Planning`.
    StartPlanning,
    /// `Planning`/`Verifying` → `ExecutingTool(tool_name)`.
    StartExecution { tool_name: String },
    /// `ExecutingTool` → `Verifying`.
    ToolSucceeded,
    /// `ExecutingTool` → `Compensating`.
    ToolFailed,
    /// `Verifying` → `Completed`.
    ValidationPassed,
    /// `Verifying` → `Compensating`.
    ValidationFailed,
    /// `Planning`/`ExecutingTool` → `AwaitingApproval` (tool irreversibile).
    RequireApproval {
        /// Tool in attesa di esecuzione.
        tool_name: String,
        /// Token generato dal kernel (UUID v4).
        approval_token: String,
    },
    /// `AwaitingApproval` → `ExecutingTool` (solo con token corrispondente).
    ApproveExecution {
        /// Deve corrispondere esattamente al token dello stato.
        approval_token: String,
    },
    /// `AwaitingApproval` → `Failed` (solo con token corrispondente).
    RejectExecution {
        /// Deve corrispondere esattamente al token dello stato.
        approval_token: String,
    },
    /// `Compensating` → `Failed`.
    CompensationCompleted,
}

impl fmt::Display for AgentEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartPlanning => write!(f, "StartPlanning"),
            Self::StartExecution { tool_name } => write!(f, "StartExecution({tool_name})"),
            Self::ToolSucceeded => write!(f, "ToolSucceeded"),
            Self::ToolFailed => write!(f, "ToolFailed"),
            Self::ValidationPassed => write!(f, "ValidationPassed"),
            Self::ValidationFailed => write!(f, "ValidationFailed"),
            Self::RequireApproval { tool_name, .. } => {
                write!(f, "RequireApproval({tool_name})")
            }
            // Token omessi di proposito: non finiscono nei log.
            Self::ApproveExecution { .. } => write!(f, "ApproveExecution"),
            Self::RejectExecution { .. } => write!(f, "RejectExecution"),
            Self::CompensationCompleted => write!(f, "CompensationCompleted"),
        }
    }
}

/// Macchina a stati dell'agente (posseduta dal Core Engine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMachine {
    current: AgentState,
}

impl StateMachine {
    /// Nuova FSM in `Idle`.
    pub fn new() -> Self {
        Self {
            current: AgentState::Idle,
        }
    }

    /// Stato corrente (riferimento).
    pub fn state(&self) -> &AgentState {
        &self.current
    }

    /// Applica un evento secondo la tabella di transizione.
    ///
    /// Su successo aggiorna lo stato interno e ritorna il nuovo stato.
    /// Su violazione ritorna `InvalidStateTransition` senza mutare lo stato.
    pub fn transition(&mut self, event: AgentEvent) -> KernelResult<AgentState> {
        let next = match (&self.current, &event) {
            (AgentState::Idle, AgentEvent::StartPlanning) => AgentState::Planning,
            (AgentState::Planning, AgentEvent::StartExecution { tool_name }) => {
                AgentState::ExecutingTool(tool_name.clone())
            }
            (AgentState::ExecutingTool(_), AgentEvent::ToolSucceeded) => AgentState::Verifying,
            (AgentState::ExecutingTool(_), AgentEvent::ToolFailed) => AgentState::Compensating,
            (AgentState::Verifying, AgentEvent::ValidationPassed) => AgentState::Completed,
            (AgentState::Verifying, AgentEvent::ValidationFailed) => AgentState::Compensating,
            (AgentState::Verifying, AgentEvent::StartExecution { tool_name }) => {
                AgentState::ExecutingTool(tool_name.clone())
            }
            // 2-Phase Commit: da Planning (flusso nominale) e da
            // ExecutingTool (flusso execute_tool: il tool è già autorizzato
            // quando il kernel rileva l'irreversibilità).
            (
                AgentState::Planning | AgentState::ExecutingTool(_),
                AgentEvent::RequireApproval {
                    tool_name,
                    approval_token,
                },
            ) => AgentState::AwaitingApproval {
                tool_name: tool_name.clone(),
                approval_token: approval_token.clone(),
            },
            // Token validato esattamente: mismatch → InvalidStateTransition.
            (
                AgentState::AwaitingApproval {
                    tool_name,
                    approval_token,
                },
                AgentEvent::ApproveExecution {
                    approval_token: presented,
                },
            ) if presented == approval_token => AgentState::ExecutingTool(tool_name.clone()),
            (
                AgentState::AwaitingApproval { approval_token, .. },
                AgentEvent::RejectExecution {
                    approval_token: presented,
                },
            ) if presented == approval_token => AgentState::Failed,
            (AgentState::Compensating, AgentEvent::CompensationCompleted) => AgentState::Failed,
            _ => {
                return Err(KernelError::InvalidStateTransition {
                    current: self.current.to_string(),
                    event: event.to_string(),
                });
            }
        };

        tracing::debug!(
            from = %self.current,
            event = %event,
            to = %next,
            "fsm transition"
        );
        self.current = next.clone();
        Ok(next)
    }

    /// Ritorna `true` SOLO se lo stato è `ExecutingTool(name)` e il nome combacia.
    ///
    /// In ogni altro stato (inclusi `Planning`, `Verifying`, `Compensating`,
    /// `Completed`, `Failed`, `Idle`) ritorna `false`.
    pub fn can_execute_tool(&self, tool_name: &str) -> bool {
        match &self.current {
            AgentState::ExecutingTool(name) => name == tool_name,
            _ => false,
        }
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}
