# ADAS 3 Runtime Support

ADAS 3 separates the canonical delivery protocol from runtime mechanics.

| Runtime | Project instructions | Native custom agents | ADAS adapter |
|---|---|---|---|
| OpenAI Codex | `AGENTS.md` | `.codex/agents/*.toml` | `.codex/` |
| OpenCode | `AGENTS.md` | `.opencode/agents/*.md` | `.opencode/` |
| Claude Code | `CLAUDE.md` (imports `AGENTS.md`) | `.claude/agents/*.md` | `.claude/` + `CLAUDE.md` |
| Cursor | `AGENTS.md` / Rules | `.cursor/agents/*.md` | `.cursor/` |

## Normalized ADAS behavior

All runtimes must preserve:

- parent/main orchestrator role
- specialized frontend/backend/QA/adversary contexts where supported
- independent QA and QA-only defect closure
- adversarial-to-defect triage
- cumulative regressions and evidence gates
- runtime preflight before autonomous implementation

Runtime-specific permission/sandbox mechanisms may be stricter than the canonical
role policy. If a runtime cannot express path-level ownership technically, the
canonical role policy remains mandatory and Git diff review provides an audit trail.

## Current official references

- Codex AGENTS.md: https://developers.openai.com/codex/guides/agents-md
- Codex subagents: https://learn.chatgpt.com/codex/agent-configuration/subagents
- OpenCode rules: https://opencode.ai/docs/rules/
- OpenCode agents: https://opencode.ai/docs/agents/
- Claude Code subagents: https://code.claude.com/docs/en/sub-agents
- Claude Code project memory: https://code.claude.com/docs/en/memory
- Cursor subagents: https://cursor.com/docs/subagents
- Cursor rules: https://cursor.com/docs/context/rules

## OpenCode alpha.3 permission profile

The generated OpenCode agents permit routine local validation commands (Git read-only inspection, test/build/lint, Playwright, adapter drift check) while broader shell/network-sensitive commands remain approval-gated. Permission interruptions should still be counted in runtime benchmarks.
