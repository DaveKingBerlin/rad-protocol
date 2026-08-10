# Changelog

## 3.0.0-alpha.3

### Project rename

- Renamed the prerelease framework from **ADHS — Autonomous Development Hyperautomation System** to **ADAS — Autonomous Development Automation System**.
- Renamed the canonical folder from `.adhs/` to `.adas/`.
- Renamed manifest key `adhs_version` to `adas_version` and Cursor command files to `adas-*`.
- Added `docs/RENAMING_ADHS_TO_ADAS.md` with the breaking-alpha migration mapping.

### Cross-runtime hardening

- Normalized CRLF/LF before canonical core hashing to prevent false adapter drift on Windows checkouts.
- Strengthened preflight as strictly read-only: findings may propose repairs, but preflight itself must never modify the workspace.
- Added/fixed Windows test-process lifecycle helpers; stale cleanup now reads `owned_pids`, `root_pid` and `listener_pid` consistently with start/stop metadata.
- Reduced predictable OpenCode permission friction for routine local validation commands while retaining approval for broader shell/network-sensitive activity.

### Naming compliance

- Added canonical `.adas/policies/public-naming.md`.
- Added a public naming audit to the final release gate when requirements use neutral/protected naming constraints.
- Naming cleanup must preserve product mechanics and acceptance criteria.

### Runtime matrix

- Added the completed OpenCode 1.18.15 / DeepSeek V4 Flash Latest Blockfall result.
- OpenCode result: 8/8 phases, 128/128 domain tests, 47/47 app tests, 15/15 E2E, 5 defects closed, final gate PASS.
- Recorded approximately 8h wall-clock, several permission-related stops and $2.34 actual provider charge.
- Added OpenRouter request-time metrics and explicitly separated wall-clock, orchestrator time and summed request generation time.

## 3.0.0-alpha.2 (released under former ADHS name)

### Public benchmark naming

- Renamed the public real-time paddle benchmark to **Paddle Duel**.
- Renamed the public falling-block benchmark to **Blockfall**.
- Renamed requirement IDs to `FR-PDL-*` and `FR-BLK-*`.
- Added the verified ADHS 3 Codex Blockfall result and token metrics.
- Public examples use neutral descriptive names while preserving the same technical benchmark scope.

### Runtime-agnostic validation

- Blockfall completed the full ADHS 3 Codex flow with 0 human interventions.
- 147/147 unit tests and 30/30 Playwright E2E tests passed.
- Four defects were independently closed; one adversarial finding was accepted and resolved.
- Generated adapters remained synchronized and the product contract hash remained unchanged.

## 3.0.0-alpha.1 (released under former ADHS name)

### Architectural change

- Introduced `.adhs/` as the canonical runtime-independent source of truth.
- Runtime folders became generated adapters rather than instruction sources.
- Added automatic adapter generation for Codex, OpenCode, Claude Code and Cursor.
- Added adapter drift checking suitable for preflight/CI.
- Added normalized runtime capability negotiation to preflight.

### Compatibility

Legacy ADHS 2.x reports, benchmarks, examples and defect/evidence conventions remain usable as historical artifacts.
