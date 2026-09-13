# RAD Protocol 3.0.0-beta.1 Package Contents

`LICENSE` is intentionally not included in this upgrade package; keep the
repository's existing GPL-3.0 license.

## Canonical source of truth

- `.rad/manifest.json`
- `.rad/core/`
- `.rad/roles/`
- `.rad/workflows/`
- `.rad/policies/`
- `.rad/schema/`

## Generator and harness

- `tools/generate_adapters.py`
- `scripts/generate-adapters.ps1`
- `scripts/generate-adapters.sh`
- `scripts/start-test-app.ps1`
- `scripts/stop-test-app.ps1`
- `scripts/cleanup-test-processes.ps1`

## Generated runtimes

- `.codex/`
- `.opencode/`
- `.claude/`
- `.cursor/`
- `CLAUDE.md`

## Shared bootstrap

- `AGENTS.md`
- `REQUIREMENTS.md`
- governance ledgers/reports
- examples/benchmarks/docs

## CI guard

- `.github/workflows/adapter-drift.yml` — fails when generated adapters drift
  from `.rad/`.

## Public examples

- `examples/snake/`
- `examples/paddle-duel/`
- `examples/blockfall/`
- `docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md`
- `docs/PUBLIC_EXAMPLE_NAMING.md`
