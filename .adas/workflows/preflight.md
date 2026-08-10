# Workflow: Harness Preflight

Perform a **strictly read-only** ADAS harness preflight. Do not implement product
functionality and do not repair the workspace during preflight.

## Read-only invariant

The preflight MUST NOT edit, create, delete, regenerate, reformat or normalize any
repository file. It MUST NOT repair adapter drift, create missing ledgers, modify
Git state, or apply a proposed tooling fix. Commands executed during preflight
must be observational/read-only.

If a check discovers a fixable problem:

1. report the finding and its classification,
2. state the exact proposed repair separately,
3. stop with a blocker when the issue prevents a trustworthy audit, and
4. wait until the repair is performed outside the preflight workflow.

A runtime that auto-repairs a discovered problem during preflight violates this
workflow even if the repair is correct.

## Runtime detection

Identify the active coding runtime (Codex, OpenCode, Claude Code, Cursor, or
other), its version when available, and the current session's effective command/
workspace capability.

The behavior of the **current session** is authoritative. PATH resolution or a
secondary launcher is diagnostic only and must not override a successful
current-session sandbox/capability probe.

## Adapter integrity

Run or conceptually verify the read-only check:

```text
python tools/generate_adapters.py --check --all
```

Generated adapter drift is a BLOCKER because adapters must correspond to the
canonical `.adas/` core. **Do not regenerate adapters during preflight.** Report
`python tools/generate_adapters.py --all` only as the proposed post-preflight
repair command.

## Checks

Classify each as `PASS`, `WARNING`, `BLOCKER`, `PHASE-1 DELIVERABLE`, or `NOT REQUIRED`:

1. `.adas/manifest.json` and canonical files are readable.
2. `REQUIREMENTS.md` exists and is treated as immutable.
3. Git is initialized/usable enough for diffs/checkpoints.
4. Current runtime sandbox/command execution works as configured.
5. Main session can read the workspace.
6. Delegated roles are discoverable/launchable in this runtime.
7. Each delegated role can execute a harmless read-only workspace probe.
8. Each role states the correct ownership boundaries.
9. Governance ledgers and evidence directories exist or can be Phase-1 setup.
10. Generated runtime/test artifacts are ignored by Git.
11. Authoritative product/browser test tooling is available or explicitly a Phase-1 deliverable.
12. Optional tooling failures are warnings unless the product contract requires them.
13. Runtime-specific limitations have a safe fallback or are reported as blockers.

For a greenfield project, missing `package.json`, application source, lockfile,
framework dependencies and Playwright config are not harness blockers if the
architecture audit assigns them to Phase 1.

End with exactly:

`READY FOR ARCHITECTURE AUDIT`

or

`BLOCKED: <short reason>`
