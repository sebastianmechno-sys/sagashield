//! Deterministic session replay dal WAL — dry-run senza side-effect.
//!
//! [`SessionReplay::replay_session`] rilegge le azioni ordinate per `seq`,
//! ricostruisce la timeline e riverifica formalmente la sequenza FSM:
//! una storia registrata che viola la tabella di transizione è corrotta
//! e il replay fallisce invece di certificarla.

use serde::{Deserialize, Serialize};

use crate::error::{KernelError, KernelResult};
use crate::fsm::{AgentEvent, StateMachine};
use crate::types::ActionStatus;
use crate::wal::Wal;

/// Un passo della timeline ricostruita.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Sequenza originale.
    pub step_seq: u64,
    /// Tool eseguito.
    pub tool_id: String,
    /// Stato finale persistito (`COMMITTED` / `COMPENSATED` / `FAILED`).
    pub status: String,
    /// Transizioni FSM simulate, in ordine (es. `StartExecution(fs.write)`).
    pub transitions: Vec<String>,
    /// `true` se lo step fu compensato dal rollback.
    pub compensated: bool,
}

/// Timeline completa di una saga, ricostruita senza rieseguire nulla.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayTimeline {
    /// Sessione riprodotta.
    pub session_id: String,
    /// Durata parete in secondi (da `created_at`/`updated_at` del WAL).
    pub duration_secs: f64,
    /// Numero di azioni registrate.
    pub total_steps: usize,
    /// Passi in ordine di esecuzione.
    pub actions_timeline: Vec<ReplayStep>,
    /// Stato FSM derivato (`Failed`, `Verifying`, ...).
    pub final_status: String,
    /// Quante compensazioni furono eseguite.
    pub compensations_executed: usize,
}

/// Replay dry-run di una sessione.
pub struct SessionReplay;

impl SessionReplay {
    /// Ricostruisce e valida formalmente la storia di una sessione.
    ///
    /// - Legge le azioni per `seq ASC`, senza chiamare alcun tool.
    /// - Simula gli eventi storici sulla FSM: `COMMITTED`/`COMPENSATED`
    ///   implicano `StartExecution` + `ToolSucceeded`; un `FAILED` senza
    ///   output implica `StartExecution` + `ToolFailed`; un `FAILED` *con*
    ///   output è un execute riuscito la cui compensazione fallì.
    /// - Un `PENDING` residuo rende il replay incoerente (lanciare prima
    ///   `recover_dangling_sessions`).
    pub fn replay_session(wal: &Wal, session_id: &uuid::Uuid) -> KernelResult<ReplayTimeline> {
        let sid = session_id.to_string();
        let actions = wal.get_actions(&sid)?;
        if actions.is_empty() {
            return Err(KernelError::SessionNotFound(sid));
        }

        let mut fsm = StateMachine::new();
        let mut timeline = Vec::with_capacity(actions.len());
        let mut compensations = 0usize;

        // Storia: Idle → Planning (ogni saga registrata è stata pianificata).
        Self::apply(&mut fsm, &sid, AgentEvent::StartPlanning)?;

        for action in &actions {
            let mut transitions = Vec::new();
            let compensated = action.status == ActionStatus::Compensated;
            if compensated {
                compensations += 1;
            }

            match action.status {
                ActionStatus::Pending | ActionStatus::PendingApproval => {
                    return Err(KernelError::InvalidStatus(format!(
                        "replay: dangling {} at seq {} (run recovery first)",
                        action.status, action.step_seq
                    )));
                }
                ActionStatus::Committed | ActionStatus::Compensated => {
                    transitions.push(Self::apply(
                        &mut fsm,
                        &sid,
                        AgentEvent::StartExecution {
                            tool_name: action.tool_id.clone(),
                        },
                    )?);
                    transitions.push(Self::apply(&mut fsm, &sid, AgentEvent::ToolSucceeded)?);
                }
                ActionStatus::Failed if action.output.is_some() => {
                    // Execute OK, compensate KO: il forward fu un successo.
                    transitions.push(Self::apply(
                        &mut fsm,
                        &sid,
                        AgentEvent::StartExecution {
                            tool_name: action.tool_id.clone(),
                        },
                    )?);
                    transitions.push(Self::apply(&mut fsm, &sid, AgentEvent::ToolSucceeded)?);
                }
                ActionStatus::Failed => {
                    transitions.push(Self::apply(
                        &mut fsm,
                        &sid,
                        AgentEvent::StartExecution {
                            tool_name: action.tool_id.clone(),
                        },
                    )?);
                    transitions.push(Self::apply(&mut fsm, &sid, AgentEvent::ToolFailed)?);
                }
            }

            timeline.push(ReplayStep {
                step_seq: action.step_seq,
                tool_id: action.tool_id.clone(),
                status: action.status.as_str().to_owned(),
                transitions,
                compensated,
            });
        }

        // Chiusura: se la simulazione è in Compensating, la storia include
        // il completamento del rollback (→ Failed).
        if *fsm.state() == crate::fsm::AgentState::Compensating {
            Self::apply(&mut fsm, &sid, AgentEvent::CompensationCompleted)?;
        }

        Ok(ReplayTimeline {
            session_id: sid.clone(),
            duration_secs: wal.session_duration_secs(&sid)?.unwrap_or(0.0),
            total_steps: actions.len(),
            actions_timeline: timeline,
            final_status: fsm.state().to_string(),
            compensations_executed: compensations,
        })
    }

    /// Applica un evento e ritorna la sua forma testuale per la timeline.
    fn apply(fsm: &mut StateMachine, sid: &str, event: AgentEvent) -> KernelResult<String> {
        let label = event.to_string();
        fsm.transition(event).map_err(|e| {
            KernelError::InvalidStatus(format!("replay incoherent for '{sid}': {e}"))
        })?;
        Ok(label)
    }
}
