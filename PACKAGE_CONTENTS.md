# ADAS 3.0.0-alpha.3 Package Contents

`LICENSE` is intentionally not included in this upgrade package; keep the
repository's existing GPL-3.0 license.

## Canonical source of truth

- `.adas/manifest.json`
- `.adas/core/`
- `.adas/roles/`
- `.adas/workflows/`
- `.adas/policies/`
- `.adas/schema/`

## Generator and lifecycle tooling

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

- `.github/workflows/adapter-drift.yml` — fails when generated adapters drift from `.adas/`.

## Public examples

- `examples/snake/`
- `examples/paddle-duel/`
- `examples/blockfall/`
- `examples/blockfall/RESULT_CODEX.md`
- `examples/blockfall/RESULT_OPENCODE.md`
- `docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md`
- `docs/PUBLIC_EXAMPLE_NAMING.md`
- `docs/RENAMING_ADHS_TO_ADAS.md`
