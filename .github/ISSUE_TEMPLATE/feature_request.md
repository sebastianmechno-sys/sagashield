---
name: Feature request
about: Propose a capability with its transactional implications
title: "feat: "
labels: enhancement
---

## Real problem

What concrete agent failure does this address? (orphaned charges, dirty
sagas, injection class, missing observability…)

## Proposed solution

API sketch (Rust and/or Python signatures), defaults, migration path.

## Transactional impact (HARD vs BEST-EFFORT)

Per `README.md` guarantees: does this change a **deterministic**
property (FSM, WAL, Step-0, local compensation) or a **best-effort**
one (remote compensations, planner behavior, OS confinement)?
How is a partial failure observed (WAL status, OTel span, MCP error)?
