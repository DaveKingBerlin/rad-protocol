# Migrating legacy ADHS 2.x to ADAS 3

ADAS 3 is the renamed continuation of the prerelease ADHS architecture. It moves
canonical delivery policy out of runtime-specific folders and into `.adas/`.

## Mapping

| legacy ADHS 2.x | ADAS 3 alpha.3+ |
|---|---|
| `AGENTS.md` full governance | `.adas/core/` + `.adas/policies/` + thin `AGENTS.md` |
| `PREFLIGHT_PROMPT.md` | `.adas/workflows/preflight.md` |
| `ARCHITECTURE_AUDIT_PROMPT.md` | `.adas/workflows/architecture-audit.md` |
| `START_PROMPT.md` | `.adas/workflows/implementation.md` |
| `RESUME_PROMPT.md` | `.adas/workflows/resume.md` |
| `.codex/agents/*` full prompts | thin generated adapters pointing to `.adas/roles/*` |

## Upgrade outline

1. Preserve the repository's existing license and product `REQUIREMENTS.md`.
2. Add the `.adas/` core.
3. Keep root `AGENTS.md` as the shared bootstrap.
4. Generate runtime adapters with `python tools/generate_adapters.py --all`.
5. Verify them with `python tools/generate_adapters.py --check --all`.
6. Commit a clean baseline.
7. Start the chosen runtime and run ADAS preflight.

Do not edit generated runtime adapter instructions directly. Change `.adas/` and
regenerate.
