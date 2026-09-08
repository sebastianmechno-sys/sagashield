//! Suite FSM Guardrail — Fase 2.
//!
//! - Happy path: Idle → Planning → ExecutingTool → Verifying → Completed.
//! - Violazioni: transizioni illegali → `InvalidStateTransition`.
//! - Ciclo di errore: ExecutingTool → Compensating → Failed.

use sagashield::{AgentEvent, AgentState, KernelError, StateMachine};

fn start_execution(tool: &str) -> AgentEvent {
    AgentEvent::StartExecution {
        tool_name: tool.to_owned(),
    }
}

#[test]
fn happy_path_to_completed() -> Result<(), KernelError> {
    let mut fsm = StateMachine::new();
    assert_eq!(fsm.state(), &AgentState::Idle);
    assert!(!fsm.can_execute_tool("tool_a"));

    assert_eq!(
        fsm.transition(AgentEvent::StartPlanning)?,
        AgentState::Planning
    );
    // In Planning nessun tool è eseguibile.
    assert!(!fsm.can_execute_tool("tool_a"));

    assert_eq!(
        fsm.transition(start_execution("tool_a"))?,
        AgentState::ExecutingTool("tool_a".to_owned())
    );
    // Solo il tool autorizzato è eseguibile.
    assert!(fsm.can_execute_tool("tool_a"));
    assert!(!fsm.can_execute_tool("tool_b"));

    assert_eq!(
        fsm.transition(AgentEvent::ToolSucceeded)?,
        AgentState::Verifying
    );
    assert!(!fsm.can_execute_tool("tool_a"));

    assert_eq!(
        fsm.transition(AgentEvent::ValidationPassed)?,
        AgentState::Completed
    );
    assert!(!fsm.can_execute_tool("tool_a"));

    Ok(())
}

#[test]
fn error_cycle_to_failed() -> Result<(), KernelError> {
    let mut fsm = StateMachine::new();
    fsm.transition(AgentEvent::StartPlanning)?;
    fsm.transition(start_execution("tool_x"))?;
    assert!(fsm.can_execute_tool("tool_x"));

    // Errore durante l'esecuzione → Compensating (blocco execute).
    assert_eq!(
        fsm.transition(AgentEvent::ToolFailed)?,
        AgentState::Compensating
    );
    assert!(!fsm.can_execute_tool("tool_x"));

    assert_eq!(
        fsm.transition(AgentEvent::CompensationCompleted)?,
        AgentState::Failed
    );
    assert!(!fsm.can_execute_tool("tool_x"));

    Ok(())
}

#[test]
fn illegal_transitions_return_violation_error() -> Result<(), KernelError> {
    // 1. Idle → ExecutingTool (salto diretto, vietato).
    let mut fsm = StateMachine::new();
    let err = fsm
        .transition(start_execution("tool_a"))
        .expect_err("Idle -> ExecutingTool deve fallire");
    assert!(
        matches!(
            &err,
            KernelError::InvalidStateTransition { current, event }
            if current == "Idle" && event == "StartExecution(tool_a)"
        ),
        "errore atteso InvalidStateTransition{{Idle, StartExecution}}, ottenuto: {err}"
    );
    // Lo stato non deve mutare dopo una violazione.
    assert_eq!(fsm.state(), &AgentState::Idle);

    // 2. Planning → ToolSucceeded (senza esecuzione, vietato).
    fsm.transition(AgentEvent::StartPlanning)?;
    let err = fsm
        .transition(AgentEvent::ToolSucceeded)
        .expect_err("Planning -> ToolSucceeded deve fallire");
    assert!(
        matches!(&err, KernelError::InvalidStateTransition { .. }),
        "ottenuto: {err}"
    );
    assert_eq!(fsm.state(), &AgentState::Planning);

    // 3. ExecutingTool → ValidationPassed (salto di Verifying, vietato).
    fsm.transition(start_execution("tool_a"))?;
    let err = fsm
        .transition(AgentEvent::ValidationPassed)
        .expect_err("ExecutingTool -> ValidationPassed deve fallire");
    assert!(
        matches!(&err, KernelError::InvalidStateTransition { .. }),
        "ottenuto: {err}"
    );

    // 4. Porta a Completed, poi verifica terminalità.
    fsm.transition(AgentEvent::ToolSucceeded)?;
    fsm.transition(AgentEvent::ValidationPassed)?;
    assert_eq!(fsm.state(), &AgentState::Completed);

    for event in [
        AgentEvent::StartPlanning,
        start_execution("tool_a"),
        AgentEvent::ToolSucceeded,
        AgentEvent::ValidationPassed,
    ] {
        let err = fsm
            .transition(event.clone())
            .expect_err("Completed è terminale: ogni evento deve fallire");
        assert!(
            matches!(
                &err,
                KernelError::InvalidStateTransition { current, .. } if current == "Completed"
            ),
            "da Completed atteso current='Completed', ottenuto: {err}"
        );
    }
    assert_eq!(fsm.state(), &AgentState::Completed);

    // 5. Failed è terminale.
    let mut failed = StateMachine::new();
    failed.transition(AgentEvent::StartPlanning)?;
    failed.transition(start_execution("tool_z"))?;
    failed.transition(AgentEvent::ToolFailed)?;
    failed.transition(AgentEvent::CompensationCompleted)?;
    assert_eq!(failed.state(), &AgentState::Failed);

    let err = failed
        .transition(AgentEvent::StartPlanning)
        .expect_err("Failed -> Planning deve fallire");
    assert!(
        matches!(
            &err,
            KernelError::InvalidStateTransition { current, event }
            if current == "Failed" && event == "StartPlanning"
        ),
        "ottenuto: {err}"
    );

    // 6. Compensating rifiuta nuovi execute.
    let mut comp = StateMachine::new();
    comp.transition(AgentEvent::StartPlanning)?;
    comp.transition(start_execution("tool_k"))?;
    comp.transition(AgentEvent::ToolFailed)?;
    assert_eq!(comp.state(), &AgentState::Compensating);
    let err = comp
        .transition(start_execution("tool_k"))
        .expect_err("Compensating -> StartExecution deve fallire");
    assert!(
        matches!(&err, KernelError::InvalidStateTransition { .. }),
        "ottenuto: {err}"
    );

    Ok(())
}

#[test]
fn can_execute_tool_matches_only_current_tool() -> Result<(), KernelError> {
    let mut fsm = StateMachine::new();
    assert!(!fsm.can_execute_tool("anything"));

    fsm.transition(AgentEvent::StartPlanning)?;
    assert!(!fsm.can_execute_tool("tool_a"));

    fsm.transition(start_execution("tool_a"))?;
    assert!(fsm.can_execute_tool("tool_a"));
    assert!(!fsm.can_execute_tool("tool_a "));
    assert!(!fsm.can_execute_tool("TOOL_A"));
    assert!(!fsm.can_execute_tool("tool_b"));

    Ok(())
}
