"""LangChain / LangGraph adapter for SagaShield.

Wraps any callable (or LangChain ``BaseTool`` when ``langchain-core`` is
installed) so that every invocation is Step-0 validated, WAL-tracked and —
if a downstream LangGraph node fails — LIFO-compensated::

    from sagashield import SagaKernel
    from sagashield.integrations.langchain import SagaShieldTool

    tool = SagaShieldTool(kernel, "fs_write", invoke=write_file,
                          compensate=delete_file)
    tool.run({"path": "workspace/a.txt", "content": "hi"})
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

try:  # optional dependency: `pip install sagashield[langchain]`
    from langchain_core.tools import BaseTool
except Exception:  # pragma: no cover - langchain absent
    BaseTool = None  # type: ignore[assignment]


class SagaShieldTool:
    """A single guarded tool bound to a :class:`SagaKernel` saga.

    The adapter drives the FSM around each call (planning → tool) so that
    LangGraph nodes stay thin: validate → WAL → execute → rollback on error.
    """

    def __init__(
        self,
        kernel,
        tool_name: str,
        invoke: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
        compensate: Optional[Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]], None]] = None,
    ) -> None:
        self._kernel = kernel
        self._name = tool_name
        self._invoke = invoke
        self._compensate = compensate
        kernel.register_tool(tool_name, invoke, compensate)

    @property
    def name(self) -> str:
        return self._name

    def _ensure(self) -> None:
        for step in (self._kernel.begin_planning,):
            try:
                step()
            except Exception:
                pass
        try:
            self._kernel.begin_tool(self._name)
        except Exception:
            pass

    def run(
        self,
        params: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Invoke through the full SagaShield pipeline."""
        self._ensure()
        return self._kernel.execute_tool(self._name, params, idempotency_key)

    def compensate(
        self,
        params: Dict[str, Any],
        output: Dict[str, Any],
    ) -> None:
        """Manual compensation entry-point (automatic rollback needs none)."""
        if self._compensate is None:
            return
        self._compensate({}, params, output)

    @classmethod
    def from_base_tool(cls, kernel, base_tool, compensate=None) -> "SagaShieldTool":
        """Adapt a LangChain ``BaseTool`` (uses its ``name`` + ``invoke``)."""
        if BaseTool is None:
            raise ImportError("langchain-core is not installed")
        if not isinstance(base_tool, BaseTool):
            raise TypeError(f"expected BaseTool, got {type(base_tool)}")

        def invoke(_ctx: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
            result = base_tool.invoke(args)
            if isinstance(result, dict):
                return result
            return {"result": result}

        return cls(kernel, base_tool.name, invoke, compensate)
