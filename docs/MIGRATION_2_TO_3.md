# Migrating legacy ADHS 2.x to RAD 3

RAD 3 is the renamed continuation of the prerelease ADHS architecture. It moves
canonical delivery policy out of runtime-specific folders and into `.rad/`.

## Mapping

| legacy ADHS 2.x | RAD 3 alpha.3+ |
|---|---|
| `AGENTS.md` full governance | `.rad/core/` + `.rad/policies/` + thin `AGENTS.md` |
| `PREFLIGHT_PROMPT.md` | `.rad/workflows/preflight.md` |
| `ARCHITECTURE_AUDIT_PROMPT.md` | `.rad/workflows/architecture-audit.md` |
| `START_PROMPT.md` | `.rad/workflows/implementation.md` |
| `RESUME_PROMPT.md` | `.rad/workflows/resume.md` |
| `.codex/agents/*` full prompts | thin generated adapters pointing to `.rad/roles/*` |

## Upgrade outline

1. Preserve the repository's existing license and product `REQUIREMENTS.md`.
2. Add the `.rad/` core.
3. Keep root `AGENTS.md` as the shared bootstrap.
4. Generate runtime adapters with `python tools/generate_adapters.py --all`.
5. Verify them with `python tools/generate_adapters.py --check --all`.
6. Commit a clean baseline.
7. Start the chosen runtime and run RAD preflight.

Do not edit generated runtime adapter instructions directly. Change `.rad/` and
regenerate.
