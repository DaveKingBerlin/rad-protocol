# Policy: Adversarial Review

All adversarial findings live in `ADVERSARIAL_REVIEW.md`.

```text
## ADV-001: Short title

- Session: phase-3 gate | final
- Suggested severity: HIGH | MEDIUM | LOW

What I did: ...
Expected: ...
Actual: ...
Screenshot: screenshots/evidence/adv-001.png (optional)

Disposition: PENDING
```

The orchestrator decides:

- `ACCEPTED -> DEF-NNN` after QA reproduces and files the defect.
- `REJECTED - reason` when the finding is outside the contract or not a defect.

No finding may remain PENDING at final release.
