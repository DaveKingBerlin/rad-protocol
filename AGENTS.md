# RAD Protocol 3 — Runtime-Agnostic Bootstrap

This repository uses **RAD Protocol — Runtime-Agnostic Delivery Protocol**.

## Canonical instructions

Before autonomous delivery, read:

1. `.rad/core/protocol.md`
2. `.rad/roles/orchestrator.md` (main/parent agent)
3. the relevant workflow under `.rad/workflows/`
4. policies under `.rad/policies/` as they become relevant

`REQUIREMENTS.md` is the immutable product contract during a build.

## Runtime adapters

`.codex/`, `.opencode/`, `.claude/`, `.cursor/` and `CLAUDE.md` are generated
runtime adapters. They are **not** the source of RAD behavior.

If an adapter and `.rad/` disagree, `.rad/` wins.

Do not hand-maintain generated adapters. Regenerate after canonical changes:

```text
python tools/generate_adapters.py --all
```

Verify no drift with:

```text
python tools/generate_adapters.py --check --all
```

## Natural-language entry points

- “Run RAD preflight.” -> `.rad/workflows/preflight.md`
- “Run RAD architecture audit.” -> `.rad/workflows/architecture-audit.md`
- “Start/continue RAD build.” -> `.rad/workflows/implementation.md`
- “Resume RAD.” -> `.rad/workflows/resume.md`
- “Run final RAD release gate.” -> `.rad/workflows/final-release.md`
