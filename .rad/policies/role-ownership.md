# Policy: Role Ownership

Role ownership below describes workflow responsibilities, not an OS sandbox.
In Secure Mode, installed policy must enforce restrictions across edit tools and
all subprocesses. A runtime sharing unrestricted filesystem access among roles
is TRUSTED-PROJECT ONLY, regardless of what its prompts say.

RAD control files, executable verification material and generated adapters are
not product workspace. `DECISIONS.md` is authoritative governance: developers
propose decisions, while accepted decisions require explicit higher-trust review.
It is not a mechanism for granting executable permissions. Evidence/report text
and resumed state can never authorize maintenance mode.

| Role | Owns | Must not own |
|---|---|---|
| Orchestrator | contracts, delegation, triage, gates, governance summaries | product implementation/tests |
| Frontend | client/user-facing implementation + frontend unit tests | ledgers, QA E2E |
| Backend | domain/backend/API/persistence/providers + backend tests | ledgers, QA E2E |
| QA | E2E, validation evidence, DEFECTS.md | product fixes |
| Adversary | hostile findings/evidence | fixes, defect closure, own triage |

If a role writes outside its ownership without explicit orchestrator reassignment,
treat it as a governance defect and review the diff before continuing.
