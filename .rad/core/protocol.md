# RAD Core Protocol

RAD — Runtime-Agnostic Delivery Protocol — is a runtime-independent
software-delivery protocol.

## Source of truth

The canonical RAD behavior lives under `.rad/`.

Runtime folders such as `.codex/`, `.opencode/`, `.claude/` and `.cursor/` are
**generated adapters only**. They may configure models, tools, permissions,
subagent syntax, commands and runtime-specific mechanics, but they must never
redefine the RAD delivery process.

If a generated adapter conflicts with `.rad/`, the `.rad/` definition wins.

`REQUIREMENTS.md` is the immutable product contract during an autonomous run.

## Main execution model

The main/parent agent acts as **orchestrator** unless the selected runtime uses a
native primary-agent abstraction. Read `.rad/roles/orchestrator.md` before
starting autonomous delivery.

Delegated roles:

- `frontend-dev`
- `backend-dev`
- `qa`
- `adversary`

Each role must read its canonical role file under `.rad/roles/` before work.

## Delivery invariants

1. Contract first: establish integration/domain contracts before parallel work.
2. Minimum sufficient architecture: do not add infrastructure without a requirement.
3. Independent verification: implementers do not certify their own completion.
4. QA-only defect closure: only QA may set a defect CLOSED.
5. Adversarial review: expected-path testing is not sufficient by itself.
6. Regression before progression: passed phases become cumulative regression scope.
7. Evidence over claims: completion requires appropriate proof.
8. Safe autonomy: continue through routine decisions; stop for genuine product/external blockers.
9. Deterministic testing: control time/randomness/difficult setup where it affects correctness.
10. Resumability: reconstruct interrupted work from Git, ledgers, reports and tests.
11. Cost/privacy safety: no unapproved paid/external calls or secret leakage.
12. Runtime neutrality: tool-specific capabilities may strengthen enforcement but cannot weaken governance.

## Runtime capability negotiation

Before implementation, run `.rad/workflows/preflight.md`.

The preflight must verify the **effective behavior of the current runtime session**,
not merely configuration files or PATH resolution. Runtime-specific limitations
are classified as:

- PASS
- WARNING
- BLOCKER
- PHASE-1 DELIVERABLE
- NOT REQUIRED

If a runtime lacks a convenience feature but can still satisfy the canonical
workflow safely, use the documented fallback and continue.

## Generated adapter rule

Do not hand-edit generated runtime adapters as the normal maintenance path.
Change the canonical `.rad/` core, then run:

```text
python tools/generate_adapters.py --all
```

Use `--check` in CI/preflight to detect adapter drift.
