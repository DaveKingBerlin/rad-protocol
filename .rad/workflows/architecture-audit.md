# Workflow: Architecture Audit

Perform a complete **read-only** architecture and scope audit before implementation.
Read `REQUIREMENTS.md` completely.

## Scope analysis

Report:

1. product/domain summary
2. current release scope and non-goals
3. MUST/SHOULD/MAY or MVP/V1/later distinctions
4. explicit open product questions
5. specification tensions/ambiguities

## Mandatory complexity budget

Answer explicitly whether the release needs:

- backend/API server
- database
- durable persistence
- routing/multiple screens
- frontend framework
- queues/workers
- external/provider services
- cloud infrastructure

Every YES requires a requirement-based justification. Prefer the **minimum
sufficient architecture**.

## Architecture

Recommend technologies, module boundaries, contracts, persistence/provider/job
architecture where applicable, frontend surfaces and release security/privacy boundaries.

## Deterministic testability

Identify timers, game loops, polling, autosave, debounce, retries, randomness,
background jobs, animation-driven state and hard-to-reproduce states. Define how
tests control or observe them deterministically. Avoid fixed sleeps where exact
state can be observed.

## Testing strategy

Cover applicable domain/unit, frontend, backend/integration, persistence-contract,
provider-contract, security, rendering, browser/E2E and adversarial validation.
State which validation runs with zero paid/external calls.

## Open questions

Classify each explicit product question:

- A: BLOCKING BEFORE IMPLEMENTATION
- B: SAFE/REQUIREMENTS DEFAULT
- C: NOT NEEDED FOR CURRENT RELEASE

Do not ask the user to decide B/C items. For A, propose a recommended decision
and explain why it blocks architecture or data contracts.

## Roadmap

Derive independently gateable phases. A substantial project commonly needs 6–10;
a small project may need fewer. You may refine coarse requirements phases into
smaller quality gates **without expanding scope**.

For every phase state scope, requirement IDs, acceptance scenarios, role work,
tests, race/determinism concerns, success criteria and dependencies.

End with exactly:

`READY FOR IMPLEMENTATION`

or

`BLOCKED: <short reason>`
