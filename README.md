# ADAS — Autonomous Development Automation System

**ADAS 3** is a runtime-agnostic, contract-first multi-agent software-delivery
protocol. The project was called ADHS in earlier prerelease versions and was
renamed to ADAS in **3.0.0-alpha.3**.

> One delivery system. Multiple coding-agent runtimes.

The canonical workflow lives in **`.adas/`**. Codex, OpenCode, Claude Code and
Cursor integrations are thin generated adapters.

## Architecture

```text
                         REQUIREMENTS.md
                               │
                               ▼
                         .adas/ CORE
                 canonical roles/workflows/policies
                               │
                    adapter generator
          ┌────────────┬────────────┬────────────┬────────────┐
          ▼            ▼            ▼            ▼
       .codex/      .opencode/    .claude/     .cursor/
        Codex        OpenCode     Claude Code     Cursor
          │            │            │            │
          └────────────┴────────────┴────────────┘
                               ▼
              Orchestrator → Devs → QA → Adversary
                               ▼
                Defect loop → Evidence gate
                               ▼
                     Validated software
```

## Canonical core

```text
.adas/
├── manifest.json
├── core/protocol.md
├── roles/
│   ├── orchestrator.md
│   ├── frontend-dev.md
│   ├── backend-dev.md
│   ├── qa.md
│   └── adversary.md
├── workflows/
│   ├── preflight.md
│   ├── architecture-audit.md
│   ├── implementation.md
│   ├── phase-gate.md
│   ├── resume.md
│   └── final-release.md
├── policies/
│   ├── role-ownership.md
│   ├── defect-lifecycle.md
│   ├── adversarial-review.md
│   ├── evidence.md
│   ├── deterministic-testing.md
│   ├── external-cost-safety.md
│   ├── git-checkpoints.md
│   ├── process-lifecycle.md
│   └── public-naming.md
└── schema/manifest.schema.json
```

## Generate adapters

Requires Python 3.9+ only; no third-party packages.

```powershell
python .\tools\generate_adapters.py --all
python .\tools\generate_adapters.py --check --all
```

Or:

```powershell
.\scripts\generate-adapters.ps1
.\scripts\generate-adapters.ps1 -Check
```

Change `.adas/`, regenerate, review the diff, commit. The included GitHub Actions
drift check rejects commits where generated adapters no longer match the
canonical core.

## Runtime adapters

- **Codex:** `AGENTS.md`, `.codex/config.toml`, `.codex/agents/*.toml`
- **OpenCode:** generated primary orchestrator + `.opencode/agents/*.md`; alpha.3
  allows routine local validation commands while retaining approval for broader
  shell/network-sensitive activity
- **Claude Code:** generated `CLAUDE.md` + `.claude/agents/*.md`
- **Cursor:** `.cursor/agents/*.md` + `/adas-*` convenience command files

See `docs/RUNTIME_SUPPORT.md`.

## Core workflow

```text
Requirements
    ↓
Strict read-only Runtime/Harness Preflight
    ↓
Architecture Audit + Complexity Budget
    ↓
Phase Contract
    ↓
Frontend + Backend/Domain (parallel when safe)
    ↓
Independent QA
    ↓
Adversarial Review
    ↓
Formal Defect Loop
    ↓
Cumulative Regression + Evidence + Naming Gate
    ↓
Git Checkpoint
    ↓
Next Phase / Final Release
```

## Quickstart

1. Put product requirements in `REQUIREMENTS.md`.
2. Generate/check adapters.
3. Start your chosen runtime.
4. Ask: **“Run ADAS preflight.”**
5. Ask: **“Run ADAS architecture audit.”**
6. Resolve only genuine A-class blockers.
7. Ask: **“Start ADAS implementation and continue through all approved phases.”**
8. If interrupted: **“Resume ADAS.”**

Cursor users also get `/adas-preflight`, `/adas-audit`, `/adas-build`,
`/adas-resume` and `/adas-release` generated as command files.

## Examples and benchmarks

The repository includes Snake, Paddle Duel and Blockfall requirements. Historical
Snake/Paddle Duel and the first two Blockfall runtime-matrix passes occurred under
the former ADHS prerelease name and remain documented as historical results.

Blockfall runtime matrix so far:

- Codex / GPT-5.6 Sol: **PASSED**
- OpenCode 1.18.15 / DeepSeek V4 Flash Latest: **PASSED**
- Claude Code: pending
- Cursor: pending

See `examples/`, `BENCHMARKS.md`, and `docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md`.

## What changed in alpha.3

- renamed ADHS → **ADAS — Autonomous Development Automation System**
- renamed canonical folder `.adhs/` → `.adas/`
- made canonical adapter hashing CRLF/LF-stable
- strengthened preflight so it reports repairs but never performs them
- fixed stale test-process metadata cleanup for `owned_pids` / `root_pid`
- added explicit public naming compliance to the final release gate
- reduced routine OpenCode validation permission friction
- added the completed OpenCode/DeepSeek Blockfall runtime-matrix result and timing/cost metrics

See `CHANGELOG.md` and `docs/RENAMING_ADHS_TO_ADAS.md`.

## Status

**3.0.0-alpha.3** — runtime-agnostic prerelease with two successful Blockfall
runtime-matrix implementations (Codex and OpenCode). Claude Code and Cursor remain
to be validated before a stable 3.0.0 release.

## License

ADAS is intended for the repository's existing **GPL-3.0** license. This upgrade
ZIP intentionally does not replace the repository's existing `LICENSE` file.

---

**ADAS — Autonomous Development Automation System**

*From requirements to validated software — autonomously, across runtimes.*
