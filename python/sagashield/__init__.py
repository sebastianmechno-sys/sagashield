"""SagaShield Python SDK — transactional guardrails for AI agents.

Typical use::

    from sagashield import SagaKernel, SecurityPolicy, transactional_tool

    @transactional_tool("fs_write", compensate_with=delete_file)
    def write_file(ctx, args):
        ...
        return {"path": args["path"]}

    kernel = SagaKernel(policy=SecurityPolicy(["./workspace"]))
    kernel.register_decorated()
    kernel.begin_planning()
    kernel.begin_tool("fs_write")
    kernel.execute_tool("fs_write", {"path": "workspace/a.txt", "content": "hi"})
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from sagashield import _core as _c
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "sagashield native module is not built. "
        "Run `maturin develop --features python` or `pip install sagashield`."
    ) from exc

__all__ = [
    "SagaKernel",
    "SecurityPolicy",
    "SecurityViolationError",
    "transactional_tool",
]

SecurityViolationError = _c.SecurityViolationError


class SecurityPolicy:
    """Sandbox policy: allowed roots, blocked filename patterns, domains."""

    def __init__(
        self,
        allowed_roots: List[str],
        blocked_patterns: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
    ) -> None:
        kwargs: Dict[str, Any] = {"allowed_roots": allowed_roots}
        if blocked_patterns is not None:
            kwargs["blocked_patterns"] = blocked_patterns
        if allowed_domains is not None:
            kwargs["allowed_domains"] = allowed_domains
        self._inner = _c.PySecurityPolicy(**kwargs)

    @property
    def _core(self):  # internal escape hatch for SagaKernel
        return self._inner


# (tool_name, execute_fn, compensate_fn) collected by the decorator.
_DECORATED: List[Tuple[str, Callable, Optional[Callable]]] = []


def transactional_tool(
    name: str,
    compensate_with: Optional[Callable] = None,
) -> Callable:
    """Mark ``fn(ctx, args) -> dict`` as a compensable SagaShield tool.

    The optional compensator has signature ``fn(ctx, args, output) -> None``.
    Register everything at once with :meth:`SagaKernel.register_decorated`.
    """

    def decorator(fn: Callable) -> Callable:
        _DECORATED.append((name, fn, compensate_with))
        fn._saga_tool = (name, compensate_with)  # type: ignore[attr-defined]
        return fn

    return decorator


def _wrap_execute(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def inner(ctx_json: str, args_json: str) -> str:
        out = fn(json.loads(ctx_json), json.loads(args_json))
        return json.dumps(out if out is not None else {})

    return inner


def _wrap_compensate(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def inner(ctx_json: str, args_json: str, output_json: str) -> str:
        fn(json.loads(ctx_json), json.loads(args_json), json.loads(output_json))
        return json.dumps({})

    return inner


class SagaKernel:
    """High-level kernel: FSM + WAL + rollback + idempotency, via Rust."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        policy: Optional[SecurityPolicy] = None,
    ) -> None:
        self._k = _c.PySagaKernel(
            db_path=db_path,
            policy=policy._core if policy is not None else None,
        )

    # -- saga driving --------------------------------------------------------

    def new_session(self) -> str:
        """Rotate the saga session id and return it."""
        return self._k.new_session()

    def session_id(self) -> str:
        """Current saga session id (for replay/audit)."""
        return self._k.session_id()

    def state(self) -> str:
        """Current FSM state."""
        return self._k.state()

    def begin_planning(self) -> str:
        return self._k.begin_planning()

    def begin_tool(self, tool_name: str) -> str:
        return self._k.begin_tool(tool_name)

    def complete(self) -> str:
        return self._k.complete()

    # -- tools ---------------------------------------------------------------

    def register_tool(
        self,
        name: str,
        execute: Callable[[Dict, Dict], Dict],
        compensate: Optional[Callable[[Dict, Dict, Dict], None]] = None,
    ) -> None:
        """Register ``execute(ctx, args) -> output`` + optional compensator."""
        self._k.register_tool(
            name,
            _wrap_execute(execute),
            _wrap_compensate(compensate) if compensate is not None else None,
        )

    def register_decorated(self) -> List[str]:
        """Register every ``@transactional_tool`` collected so far."""
        names = []
        for name, fn, comp in list(_DECORATED):
            self.register_tool(name, fn, comp)
            names.append(name)
        return names

    def execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run one guarded step; returns the output payload as dict."""
        raw = self._k.execute_tool(tool_name, json.dumps(params), idempotency_key)
        return json.loads(raw)

    # -- retrospective -------------------------------------------------------

    def replay_session(self, session_id: str) -> Dict[str, Any]:
        """Deterministic dry-run replay of a past saga."""
        return json.loads(self._k.replay_session(session_id))

    def export_audit_otel(self, session_id: str) -> Dict[str, Any]:
        """Session audit as OpenTelemetry ``resourceSpans`` dict."""
        return json.loads(self._k.export_audit_otel(session_id))
