//! Structured audit export in formato OpenTelemetry — ingestione pronta
//! per Datadog, Honeycomb o Jaeger.
//!
//! Nessuna dipendenza OTel runtime: l'export è JSON conforme a
//! `resourceSpans/scopeSpans/spans`, mentre gli span `tracing` del kernel
//! usano già nomi di attributi compatibili OTel (ponte diretto via
//! `tracing-opentelemetry` quando serve lo streaming live).

use serde_json::{Value, json};

use crate::error::{KernelError, KernelResult};
use crate::types::ActionStatus;
use crate::wal::Wal;

/// Esportazione audit di una sessione.
pub struct AuditExporter;

impl AuditExporter {
    /// Esporta la sessione come JSON OTel (`resourceSpans`).
    ///
    /// Ogni azione WAL diventa uno span: `traceId` deterministico dalla
    /// sessione, `spanId` da `(sessione, seq)`, catena `parentSpanId`,
    /// tempi Unix-nano dai timestamp SQLite, attributi semantici
    /// (`agent.session_id`, `agent.tool.name`, `agent.tool.idempotency_key`,
    /// `agent.fsm.state`, `agent.rollback.triggered`, `security.violation.type`
    /// quando pertinente) e `status` OK/ERROR.
    pub fn export_session_otel_json(wal: &Wal, session_id: &uuid::Uuid) -> KernelResult<String> {
        let sid = session_id.to_string();
        let actions = wal.get_actions(&sid)?;
        if actions.is_empty() {
            return Err(KernelError::SessionNotFound(sid));
        }

        let rolled_back = actions
            .iter()
            .any(|a| a.status == ActionStatus::Compensated);
        let trace_id = format!(
            "{:016x}{:016x}",
            fnv1a64(&format!("{sid}:trace:a")),
            fnv1a64(&format!("{sid}:trace:b"))
        );

        let mut spans = Vec::with_capacity(actions.len());
        for (i, action) in actions.iter().enumerate() {
            let span_id = format!(
                "{:016x}",
                fnv1a64(&format!("{sid}:{}:span", action.step_seq))
            );
            let start_nanos = sqlite_ts_nanos(&action.created_at)?;
            let end_nanos = sqlite_ts_nanos(&action.updated_at)?;
            let (fsm_state, status_code) = match action.status {
                ActionStatus::Pending => ("Pending", 0),
                ActionStatus::PendingApproval => ("AwaitingApproval", 0),
                ActionStatus::Committed => ("Verifying", 1),
                ActionStatus::Compensated => ("Failed", 1),
                ActionStatus::Failed => ("Compensating", 2),
            };
            let rollback_triggered = rolled_back && action.status != ActionStatus::Pending;

            let mut attrs = vec![
                attr_str("agent.session_id", &sid),
                attr_str("agent.tool.name", &action.tool_id),
                attr_str("agent.tool.idempotency_key", &action.idempotency_key),
                attr_str("agent.fsm.state", fsm_state),
                attr_bool("agent.rollback.triggered", rollback_triggered),
                attr_str("agent.action.status", action.status.as_str()),
            ];
            if let Some(err) = action.error.as_deref() {
                attrs.push(attr_str("exception.message", err));
                if err.to_lowercase().contains("security violation")
                    || err.to_lowercase().contains("traversal")
                    || err.to_lowercase().contains("blocked")
                    || err.to_lowercase().contains("unauthorized")
                {
                    attrs.push(attr_str("security.violation.type", "step0_block"));
                }
            }

            let mut span = json!({
                "traceId": trace_id,
                "spanId": span_id,
                "name": action.tool_id,
                "kind": 1,
                "startTimeUnixNano": start_nanos.to_string(),
                "endTimeUnixNano": end_nanos.to_string(),
                "attributes": attrs,
                "status": {"code": status_code},
            });
            if i > 0 {
                span["parentSpanId"] = Value::String(format!(
                    "{:016x}",
                    fnv1a64(&format!("{sid}:{}:span", actions[i - 1].step_seq))
                ));
            }
            spans.push(span);
        }

        let doc = json!({
            "resourceSpans": [{
                "resource": {"attributes": [
                    {"key": "service.name", "value": {"stringValue": "sagashield"}},
                    {"key": "service.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}},
                ]},
                "scopeSpans": [{
                    "scope": {"name": "sagashield"},
                    "spans": spans,
                }],
            }],
        });
        serde_json::to_string_pretty(&doc).map_err(KernelError::from)
    }
}

fn attr_str(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn attr_bool(key: &str, value: bool) -> Value {
    json!({"key": key, "value": {"boolValue": value}})
}

/// FNV-1a 64 bit (ID deterministici senza dipendenze).
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// `"YYYY-MM-DD HH:MM:SS"` (UTC, SQLite) → nanosecondi Unix.
fn sqlite_ts_nanos(ts: &str) -> KernelResult<i64> {
    let invalid = || KernelError::InvalidStatus(format!("bad timestamp '{ts}'"));
    let (date, time) = ts.split_once(' ').ok_or_else(invalid)?;
    let mut d = date.split('-');
    let (y, m, day) = (
        d.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
        d.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
        d.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
    );
    let mut t = time.split(':');
    let (hh, mm, ss) = (
        t.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
        t.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
        t.next()
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())?,
    );
    let days = days_from_civil(y, m, day);
    Ok((days * 86_400 + hh * 3_600 + mm * 60 + ss) * 1_000_000_000)
}

/// Giorni da Unix epoch (algoritmo civile di Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
