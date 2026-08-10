# Workflow: Resume Interrupted Run

Resume from the current repository state after quota, approval, runtime, process
or machine interruption.

## Reconstruct

Inspect Git history/status, phase checkpoints, `DEFECTS.md`,
`ADVERSARIAL_REVIEW.md`, `POC_REPORT.md`, current tests, current working tree and
available artifacts.

Identify:

- last fully gated phase
- current in-progress phase
- implementation already complete
- validation already authored
- validation still waiting to run
- pending adversarial work
- OPEN/FIX-READY/DISPUTED defects
- intentional uncommitted phase work

## Cleanup

Verify old test processes/ports, PID metadata, stale browser artifacts and
unintentionally rewritten evidence. Stop only processes demonstrably owned by the
interrupted run.

## Continue

Resume from the earliest genuinely incomplete gate step. Do not rewrite completed
implementation just because execution was interrupted.

Record interruption reason, human action and whether rework was necessary in PoC
reporting when enabled, then continue remaining phases automatically.
