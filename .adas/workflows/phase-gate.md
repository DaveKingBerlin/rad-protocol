# Workflow: Phase Gate

A phase passes only when all of the following are true:

- bounded implementation tasks completed
- accepted contracts still hold or approved changes are documented
- relevant developer tests pass
- QA independently validates phase behavior
- cumulative regression baseline remains green
- adversarial phase pass completed
- every accepted adversarial finding is triaged into the formal defect process
- all blocking OPEN/FIX-READY/DISPUTED defects are resolved/closed as required
- every phase success criterion has concrete evidence
- runtime/browser/process cleanup is complete
- worktree is coherent/checkpointable

Do not treat “developer says done” as a phase gate.
