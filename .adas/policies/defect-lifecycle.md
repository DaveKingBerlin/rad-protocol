# Policy: Defect Lifecycle

All formal defects live in `DEFECTS.md`.

```text
## DEF-001: Short title

- Status: OPEN
- Severity: HIGH | MEDIUM | LOW
- Found by: qa | adversary (ADV-003)
- Phase: 3

Steps to reproduce:
1. ...

Expected: ...
Actual: ...
Screenshot: screenshots/evidence/def-001.png (optional)

History:
- qa: opened
```

Statuses:

| Status | Meaning | Set by |
|---|---|---|
| OPEN | filed/reopened | QA |
| FIX-READY | developer reports fix | Orchestrator relaying developer |
| DISPUTED | cannot reproduce / working as intended | Orchestrator relaying developer |
| CLOSED | independent retest passes | QA only |
| REJECTED | will not fix with rationale | Orchestrator only |

Developers report exactly one outcome: `FIX READY`, `CANNOT REPRODUCE`, or
`WORKING AS INTENDED`. Every state change appends History. Developer confidence
never closes a defect.
