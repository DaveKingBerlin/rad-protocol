# RAD Protocol

**RAD — Runtime-Agnostic Delivery** is a contract-first, runtime-independent
software-delivery protocol for autonomous coding agents.

> **One delivery protocol. Any agent runtime.**
>
> *Don't reinvent the wheel. Run RAD.*

The canonical workflow lives in **`.rad/`**. Codex, OpenCode, Claude Code and
Cursor integrations are thin generated adapters around the same roles, workflows
and policies.

> **Platform scope:** hostile-project Secure Mode is certified only for a
> pinned Codex CLI inside a dedicated hardened WSL2 distribution; native
> Windows Codex and OpenCode/Claude Code/Cursor remain TRUSTED-PROJECT ONLY.
> The test-process lifecycle wrappers (`scripts/*-test-app.ps1`,
> `cleanup-test-processes.ps1`) are Windows-only by design.

## Architecture

```text
                         REQUIREMENTS.md
                               │
                               ▼
                          .rad/ CORE
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

The runtime changes. The delivery protocol does not.

## Canonical core

```text
.rad/
├── manifest.json
├── core/
│   └── protocol.md
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
└── schema/
    └── manifest.schema.json
```

Runtime adapter files contain only runtime mechanics and pointers back to these
canonical instructions.

## Generate adapters

Requires Python 3.9+ only; no third-party packages.

```powershell
python .\tools\generate_adapters.py --all
python .\tools\generate_adapters.py --check --all
```

Or on PowerShell:

```powershell
.\scripts\generate-adapters.ps1
.\scripts\generate-adapters.ps1 -Check
```

Change `.rad/`, regenerate, review the diff, commit. The included GitHub Actions
drift check rejects commits where generated adapters no longer match the
canonical core.

## Runtime adapters

### OpenAI Codex

- shared project bootstrap: `AGENTS.md`
- custom delegated agents: `.codex/agents/*.toml`
- runtime config: `.codex/config.toml`
- main Codex thread acts as orchestrator

### OpenCode

- shared project bootstrap: `AGENTS.md`
- generated primary orchestrator + delegated agents: `.opencode/agents/*.md`
- OpenCode permissions can strengthen canonical role ownership while allowing
  routine local validation commands

### Claude Code

- generated `CLAUDE.md` imports shared `AGENTS.md`
- delegated agents: `.claude/agents/*.md`
- main Claude session acts as orchestrator

### Cursor

- shared `AGENTS.md`
- delegated agents: `.cursor/agents/*.md`
- convenience commands: `.cursor/commands/rad-*.md`
- main Cursor Agent acts as orchestrator

See [`docs/RUNTIME_SUPPORT.md`](docs/RUNTIME_SUPPORT.md).

## Core workflow

```text
Requirements
    ↓
Runtime/Harness Preflight
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
Cumulative Regression + Evidence Gate
    ↓
Git Checkpoint
    ↓
Next Phase / Final Release
```

## Quickstart

1. Put product requirements in `REQUIREMENTS.md`.
2. Generate/check adapters.
3. Start your chosen runtime.
4. Ask: **“Run RAD preflight.”**
5. Ask: **“Run RAD architecture audit.”**
6. Resolve only genuine A-class blockers.
7. Ask: **“Start RAD implementation and continue through all approved phases.”**
8. If interrupted: **“Resume RAD.”**

Cursor users also get `/rad-preflight`, `/rad-audit`, `/rad-build`,
`/rad-resume` and `/rad-release` generated as commands.

## Examples and benchmarks

The repository includes example requirements for Snake, Paddle Duel and
Blockfall. Snake and Paddle Duel validated the legacy ADHS 2.x process. Blockfall
is the first verified runtime-matrix benchmark for the runtime-independent 3.x
architecture.

The same Blockfall contract completed successfully under both:

- Codex / GPT-5.6 Sol
- OpenCode 1.18.15 / DeepSeek V4 Flash Latest via OpenRouter

See `examples/`, `BENCHMARKS.md` and
`docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md`.

## Status

**3.0.0-beta.1** — first beta release of RAD Protocol.

RAD has now completed multiple autonomous software-delivery benchmarks across different project types and runtime/model combinations.

The canonical `.rad/` core, generated runtime adapters, formal QA/defect lifecycle, adversarial review, deterministic testing policies and final release gates have all been exercised successfully in repeated end-to-end runs.

Current beta focus:

- additional runtime-matrix validation
- permission-profile refinement
- runtime-specific friction reduction
- broader project diversity
- benchmark consistency
- documentation and onboarding
- stabilization toward `3.0.0`

## Origins & Acknowledgements

Inspired in part by Ed Donner’s public multi-agent development setup, especially the separation of orchestration, implementation, QA and adversarial review. RAD Protocol has since evolved into a runtime-agnostic delivery and governance protocol with generated adapters for multiple agent runtimes.


## License

RAD Protocol is intended for the repository's existing **GPL-3.0** license. This
upgrade package intentionally does not replace the repository's existing
`LICENSE` file.

---

**RAD Protocol — Runtime-Agnostic Delivery Protocol**

*From requirements to validated software — autonomously, across runtimes.*
# Security notice

Direct runtime adapters are **TRUSTED-PROJECT ONLY**.
