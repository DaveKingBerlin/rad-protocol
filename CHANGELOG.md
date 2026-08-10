# Changelog

## 3.0.0-alpha.3

### Project identity

- Renamed the project to **RAD Protocol — Runtime-Agnostic Delivery Protocol**.
- Renamed canonical `.adhs/` / intermediate `.adas/` references to `.rad/`.
- Renamed manifest key to `rad_version` and Cursor commands to `/rad-*`.
- Generated runtime adapters now point only to the canonical `.rad/` core.

### Cross-runtime validation

- Added the verified Blockfall OpenCode 1.18.15 / DeepSeek V4 Flash Latest run.
- OpenCode completed 8/8 phases with 128/128 domain tests, 47/47 app tests and
  15/15 Playwright E2E tests.
- Five defects were independently closed and no adversarial findings remained
  pending at final release.
- Canonical core overrides required: 0.
- Manual OpenCode adapter edits required: 0.
- Actual OpenRouter provider charge: $2.34.
- Wall-clock elapsed: approximately 8h; orchestrator-reported active time:
  approximately 1h 21m.
- OpenRouter activity export: 1,304 requests; adjusted summed generation time
  approximately 7h 48m after excluding one apparent stalled request.

### Harness hardening

- Normalize CRLF/LF before canonical-core hashing so Windows checkouts do not
  produce false adapter drift.
- Correct Windows test-process cleanup to use `owned_pids`, `root_pid` and
  `listener_pid` metadata consistently.
- Preflight is explicitly read-only: it reports harness problems but does not
  repair or regenerate during the preflight itself.
- Added public naming compliance to the canonical final release gate.
- OpenCode generated permissions allow routine local validation while keeping
  package installation/network-sensitive operations approval-gated.

## 3.0.0-alpha.2

### Public benchmark naming

- Renamed the public real-time paddle benchmark to **Paddle Duel**.
- Renamed the public falling-block benchmark to **Blockfall**.
- Renamed requirement IDs to `FR-PDL-*` and `FR-BLK-*`.
- Added the verified ADHS 3 Codex Blockfall result and token metrics.
- Public examples use neutral descriptive names while preserving benchmark scope.

### Runtime-agnostic validation

- Blockfall completed the full ADHS 3 Codex flow with 0 human interventions.
- 147/147 unit tests and 30/30 Playwright E2E tests passed.
- Four defects were independently closed; one adversarial finding was accepted
  and resolved.
- Generated adapters remained synchronized and the product contract hash remained
  unchanged.

## 3.0.0-alpha.1

### Architectural change

- Introduced a canonical runtime-independent source of truth (then `.adhs/`).
- Runtime folders became generated adapters rather than instruction sources.
- Added automatic adapter generation for Codex, OpenCode, Claude Code and Cursor.
- Added adapter drift checking suitable for preflight/CI.
- Added normalized runtime capability negotiation to preflight.

### Compatibility

Legacy ADHS 2.x reports, benchmarks, examples and defect/evidence conventions
remain usable.
