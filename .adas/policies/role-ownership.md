# Policy: Role Ownership

Role ownership is mandatory even when a runtime gives several agents the same
filesystem permissions. Runtime-specific permissions may strengthen this policy
but are not the source of truth.

| Role | Owns | Must not own |
|---|---|---|
| Orchestrator | contracts, delegation, triage, gates, governance summaries | product implementation/tests |
| Frontend | client/user-facing implementation + frontend unit tests | ledgers, QA E2E |
| Backend | domain/backend/API/persistence/providers + backend tests | ledgers, QA E2E |
| QA | E2E, validation evidence, DEFECTS.md | product fixes |
| Adversary | hostile findings/evidence | fixes, defect closure, own triage |

If a role writes outside its ownership without explicit orchestrator reassignment,
treat it as a governance defect and review the diff before continuing.
