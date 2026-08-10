# Workflow: Autonomous Implementation

Use the accepted architecture audit/roadmap and `REQUIREMENTS.md` as the contract.
The main agent is the orchestrator.

For each approved phase:

1. read relevant requirements and prior contracts
2. define/refine the phase contract before parallel implementation
3. record significant ADRs where useful
4. create bounded frontend/backend task specs
5. delegate independent implementation in parallel when safe/runtime-supported
6. wait for results and review integration evidence
7. return corrections to the responsible developer
8. have QA author/run phase validation and cumulative regressions
9. have adversary perform a focused hostile pass
10. triage every adversarial finding
11. have QA reproduce accepted findings and create formal defects
12. dispatch OPEN defects to the responsible developer
13. record developer outcome as FIX-READY or DISPUTED
14. have QA independently retest
15. repeat until no blocking defect remains
16. verify every phase criterion individually with evidence
17. update PoC/benchmark metrics when enabled
18. leave a coherent Git checkpoint
19. close/retire completed role contexts where runtime-supported
20. continue to the next approved phase automatically

Do not stop between successful phases. Stop only for a genuine blocker requiring
product/user/external action.

Do not introduce architecture rejected by the accepted complexity budget.
Follow deterministic testing, evidence, cost and process-lifecycle policies.
