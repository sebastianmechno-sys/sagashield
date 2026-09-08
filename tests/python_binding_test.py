"""End-to-end validation of the SagaShield Python bindings.

Run from the repo root:  python tests/python_binding_test.py

- Test 1: register 2 Python tools (file writer + payment simulator).
- Test 2: third step raises an intentional Python RuntimeError.
- Test 3: the Rust kernel catches it, runs LIFO Python compensations,
  and the file is physically gone.
- Test 4: path traversal from Python is blocked at Step-0 with the typed
  SecurityViolationError.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sagashield import (
    SagaKernel,
    SecurityPolicy,
    SecurityViolationError,
    transactional_tool,
)

WORKSPACE = tempfile.mkdtemp(prefix="sagashield_py_")
LEDGER: dict = {}
PASS = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    PASS.append(bool(cond))


def delete_file(ctx, args, output):
    path = args["path"]
    if os.path.exists(path):
        os.remove(path)


@transactional_tool("py_write", compensate_with=delete_file)
def write_file(ctx, args):
    with open(args["path"], "w", encoding="utf-8") as fh:
        fh.write(args["content"])
    return {"path": args["path"]}


def refund(ctx, args, output):
    LEDGER[args["payment_id"]] = "REFUNDED"


@transactional_tool("py_pay", compensate_with=refund)
def charge(ctx, args):
    LEDGER[args["payment_id"]] = "CHARGED"
    return {"payment_id": args["payment_id"]}


@transactional_tool("py_boom")
def boom(ctx, args):
    raise RuntimeError("intentional python crash")


def main():
    kernel = SagaKernel(policy=SecurityPolicy([WORKSPACE]))
    names = kernel.register_decorated()
    check("Test 1a: decorator registration", set(names) == {"py_write", "py_pay", "py_boom"}, str(names))

    target = os.path.join(WORKSPACE, "order.txt")
    kernel.begin_planning()
    kernel.begin_tool("py_write")
    out = kernel.execute_tool("py_write", {"path": target, "content": "order-42"})
    check("Test 1b: file tool executes", out.get("path") == target and os.path.exists(target))
    kernel.begin_tool("py_pay")
    kernel.execute_tool("py_pay", {"payment_id": "pay-py-1"})
    check("Test 1c: payment tool executes", LEDGER.get("pay-py-1") == "CHARGED")

    # Test 2: intentional crash mid-saga.
    kernel.begin_tool("py_boom")
    try:
        kernel.execute_tool("py_boom", {})
        crashed = False
    except RuntimeError as exc:
        crashed = "intentional python crash" in str(exc)
    check("Test 2: RuntimeError surfaces to Python", crashed)

    # Test 3: LIFO compensations ran (refund before delete).
    check("Test 3a: payment refunded by compensate", LEDGER.get("pay-py-1") == "REFUNDED")
    check("Test 3b: file physically deleted", not os.path.exists(target))
    check("Test 3c: FSM terminal Failed", kernel.state() == "Failed", kernel.state())

    # Test 4: traversal blocked at Step-0 with typed error.
    kernel2 = SagaKernel(policy=SecurityPolicy([WORKSPACE]))
    kernel2.register_tool("py_write", write_file, delete_file)
    kernel2.begin_planning()
    kernel2.begin_tool("py_write")
    evil = os.path.join(WORKSPACE, "..", "..", ".env")
    try:
        kernel2.execute_tool("py_write", {"path": evil, "content": "pwned"})
        blocked = False
    except SecurityViolationError:
        blocked = True
    except Exception as exc:  # noqa: BLE001 - must be the typed error
        print(f"  (wrong exception type: {type(exc).__name__}: {exc})")
        blocked = False
    check("Test 4: SecurityViolationError on traversal", blocked)

    # Bonus: replay + audit through the bindings, on the crashed saga.
    sid = kernel.session_id()
    timeline = kernel.replay_session(sid)
    check(
        "Bonus 1: replay timeline (3 steps, Failed)",
        timeline.get("total_steps") == 3
        and timeline.get("final_status") == "Failed"
        and timeline.get("compensations_executed") == 2,
        f"steps={timeline.get('total_steps')} status={timeline.get('final_status')}",
    )
    audit = kernel.export_audit_otel(sid)
    spans = audit["resourceSpans"][0]["scopeSpans"][0]["spans"]
    has_session = any(
        any(
            a.get("key") == "agent.session_id"
            and a.get("value", {}).get("stringValue") == sid
            for a in s.get("attributes", [])
        )
        for s in spans
    )
    has_rb = any(
        any(
            a.get("key") == "agent.rollback.triggered"
            and a.get("value", {}).get("boolValue") is True
            for a in s.get("attributes", [])
        )
        for s in spans
    )
    check("Bonus 2: audit spans carry session id", has_session, f"{len(spans)} spans")
    check("Bonus 3: rollback.triggered=true present", has_rb)
    print(f"[INFO] workspace={WORKSPACE} ledger={LEDGER}")

    failed = [p for p in PASS if not p]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
