# RAD Protocol 3 Runtime Support

RAD 3 separates the canonical delivery protocol from runtime mechanics.

| Runtime | Project instructions | Native custom agents | RAD adapter |
|---|---|---|---|
| OpenAI Codex | `AGENTS.md` | `.codex/agents/*.toml` | `.codex/` |
| OpenCode | `AGENTS.md` | `.opencode/agents/*.md` | `.opencode/` |
| Claude Code | `CLAUDE.md` (imports `AGENTS.md`) | `.claude/agents/*.md` | `.claude/` + `CLAUDE.md` |
| Cursor | `AGENTS.md` / Rules | `.cursor/agents/*.md` | `.cursor/` |

## Normalized RAD behavior

All runtimes must preserve:

- parent/main orchestrator role
- specialized frontend/backend/QA/adversary contexts where supported
- independent QA and QA-only defect closure
- adversarial-to-defect triage
- cumulative regressions and evidence gates
- runtime preflight before autonomous implementation

Workflow instructions are not technical isolation. Direct adapters remain
TRUSTED-PROJECT ONLY. Secure startup requires the externally pinned launcher and
native proof of the entire execution path. See `docs/SECURE_MODE.md`.

## Current official references

- Codex AGENTS.md: https://developers.openai.com/codex/guides/agents-md
- Codex subagents: https://learn.chatgpt.com/codex/agent-configuration/subagents
- OpenCode rules: https://opencode.ai/docs/rules/
- OpenCode agents: https://opencode.ai/docs/agents/
- Claude Code subagents: https://code.claude.com/docs/en/sub-agents
- Claude Code project memory: https://code.claude.com/docs/en/memory
- Cursor subagents: https://cursor.com/docs/subagents
- Cursor rules: https://cursor.com/docs/context/rules

## Secure Mode capability matrix (Phase 2D)

| Runtime | Version tested | Filesystem | Network | Project-extension startup | Credential environment | Process isolation | Control-plane writes | Native test | Secure Mode status |
|---|---|---|---|---|---|---|---|---|---|---|
| Codex (WSL2 `RAD-Secure-Test`) | 0.153.4 linux | Linux ext4 workspace; `/mnt/c`, `/mnt/d`, host profile not present; outside-workspace writes read-only | `socket()` denied with EPERM (private netns, no routes, DNS blocked); no host gateway/hostname/LAN/Internet reachable, for command and descendants | Project runs in Linux filesystem; no host extension startup | Constructed allowlist env; clean distro, no credential stores; codex pinned | Non-root bwrap process tree | Root-owned immutable control files (`chattr +i`) deny write/chmod/rm/rename-over at OS layer | Native probes and the committed WSL regression suite; hostile fixture executes in-sandbox | **SUPPORTED** |
| Codex (native Windows) | 0.154.0 | Project writes denied / host reads denied (probe) | Host loopback reachable from socket clients in every CLI sandbox mode | Unverified | Launcher allowlist tested | Restricted token/job only | Guard/broker tested; runtime write path unverified | Loopback-network denial failed Phase 2B/2C | TRUSTED-PROJECT ONLY |
| OpenCode | Not verified | Unverified | Unverified | Project plugin suppression unverified | Launcher allowlist only | Unverified | Verifier only | Not performed successfully | TRUSTED-PROJECT ONLY |
| Claude Code | Not available | Unverified | Unverified | Unverified | Launcher allowlist only | Unverified | Verifier only | Not performed | TRUSTED-PROJECT ONLY |
| Cursor | Not available | Unverified | Unverified | Unverified | Launcher allowlist only | Unverified | Verifier only | Not performed | TRUSTED-PROJECT ONLY |

Only the Codex WSL2 combination is SUPPORTED for hostile-project Secure Mode.
The launcher refuses every uncertified backend/platform combination before
starting an executable. A platform/runtime/version is part of the
certification; "Codex" is not generically secure. OpenCode/Claude/Cursor
remain for trusted projects only.

## Control-plane guard (Phase 2C)

For all runtimes, a trusted-project session now requires
`--guard-control-plane`: the repository control plane is locked with reversible
Windows deny ACLs (write/truncate/delete/rename-over/create denied at the OS
boundary for every process and descendant) and shown to be locked before the
runtime executable starts, then restored exactly when the session ends. Direct
agent file tools and every child/grandchild of the runtime therefore inherit the
same OS boundary. This binds tools, shell commands, test frameworks, plugins,
formatters, MCP servers and arbitrary descendants to the control-plane boundary
independent of model cooperation or prompt instructions.

## Direct OpenCode adapter permissions

The automatic shell allowlist is empty. Git inspection, tests, builds, linters,
Playwright and the local generator require review. Read/search tools remain
available. Auto mode can approve asks; these permissions are defense in depth,
not a sandbox or a guarantee against project plugins, formatters, LSP or MCP tools.
