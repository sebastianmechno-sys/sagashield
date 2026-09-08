"""Realistic LangGraph/CrewAI-style pipeline protected by SagaShield.

Run from the repo root (after `maturin develop --features python`):

    python examples/python_agent_demo.py

A planner node writes an order file, a billing node charges the customer,
then a shipping node crashes (simulated carrier outage). SagaShield rolls
back charge + file automatically; the audit trail is exported as OTel JSON.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sagashield import SagaKernel, SecurityPolicy, transactional_tool

WORKSPACE = tempfile.mkdtemp(prefix="sagashield_demo_")
LEDGER = {}


def remove_file(ctx, args, output):
    if os.path.exists(args["path"]):
        os.remove(args["path"])
        print(f"  [compensate] deleted {args['path']}")


@transactional_tool("write_order", compensate_with=remove_file)
def write_order(ctx, args):
    with open(args["path"], "w", encoding="utf-8") as fh:
        fh.write(args["content"])
    print(f"  [node:plan] wrote {args['path']}")
    return {"path": args["path"]}


def refund_charge(ctx, args, output):
    LEDGER[args["payment_id"]] = "REFUNDED"
    print(f"  [compensate] refunded {args['payment_id']}")


@transactional_tool("charge_customer", compensate_with=refund_charge)
def charge_customer(ctx, args):
    LEDGER[args["payment_id"]] = "CHARGED"
    print(f"  [node:bill] charged {args['payment_id']} ({args['amount']}c)")
    return {"payment_id": args["payment_id"]}


@transactional_tool("ship_order")
def ship_order(ctx, args):
    # Simulated carrier outage mid-graph (LangGraph node failure).
    raise RuntimeError("carrier API 503: shipping unavailable")


def main():
    print("=== SagaShield × Python agent demo ===")
    kernel = SagaKernel(policy=SecurityPolicy([WORKSPACE]))
    kernel.register_decorated()
    session = kernel.new_session()
    print(f"saga session: {session}")

    order = os.path.join(WORKSPACE, "order-7.txt")
    kernel.begin_planning()
    kernel.begin_tool("write_order")
    kernel.execute_tool("write_order", {"path": order, "content": "7 × widgets"})
    kernel.begin_tool("charge_customer")
    kernel.execute_tool(
        "charge_customer",
        {"payment_id": "demo-pay-7", "amount": 1999},
        idempotency_key="demo-7",
    )

    kernel.begin_tool("ship_order")
    try:
        kernel.execute_tool("ship_order", {"order": order})
    except RuntimeError as exc:
        print(f"[graph] node failed, kernel rolled back: {exc}")

    print(f"[graph] ledger={LEDGER} file_gone={not os.path.exists(order)}")
    print(f"[graph] fsm={kernel.state()}")
    timeline = kernel.replay_session(kernel.session_id())
    print(
        f"[graph] replay: {timeline['total_steps']} steps, "
        f"{timeline['compensations_executed']} compensations, "
        f"final={timeline['final_status']}"
    )


if __name__ == "__main__":
    main()
