# ADAS 3 — Runtime-Agnostic Bootstrap

This repository uses **ADAS — Autonomous Development Automation System**.

`REQUIREMENTS.md` is the immutable product contract during an autonomous run.

## Canonical instruction order

1. `.adas/core/protocol.md`
2. `.adas/roles/orchestrator.md` (main/parent agent)
3. the relevant workflow under `.adas/workflows/`
4. policies under `.adas/policies/` as they become relevant

Runtime folders such as `.codex/`, `.opencode/`, `.claude/` and `.cursor/` are
generated adapters. They are **not** the source of ADAS behavior. If an adapter
and `.adas/` disagree, `.adas/` wins.

## Role model

- orchestrator: plans, delegates, triages and gates; does not implement product code
- frontend-dev: frontend/client implementation and frontend unit tests
- backend-dev: backend/domain/storage/provider implementation and domain tests
- qa: independent E2E/product verification, evidence and defect closure
- adversary: hostile edge-case/security/reliability review; never fixes findings

Only QA may mark defects CLOSED.

## Workflow phrases

- “Run ADAS preflight.” → `.adas/workflows/preflight.md`
- “Run ADAS architecture audit.” → `.adas/workflows/architecture-audit.md`
- “Start/continue ADAS build.” → `.adas/workflows/implementation.md`
- “Resume ADAS.” → `.adas/workflows/resume.md`
- “Run final ADAS release gate.” → `.adas/workflows/final-release.md`

Before autonomous product work, verify generated adapters with:

```text
python tools/generate_adapters.py --check --all
```
