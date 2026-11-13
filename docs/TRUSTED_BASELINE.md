# Trusted RAD installation and baseline

RAD Secure Mode separates two locations:

```text
verified, release-pinned RAD installation
    establishes policy and verifies its own release digest
    verifies protected project files without running project code
untrusted target repository
```

The trusted installation must be outside, and not nested above or below, the
target repository. The launcher must receive the expected release SHA-256 from
an independent installation record or release channel. It must not calculate
the expected value from the mutable target or accept a value proposed by target
instructions, model output, reports, resumed state, environment files, or test
output.

This first version is release-pinned but not cryptographically signed. Its trust
assumption is that the operator obtains the expected release digest through an
independent trusted channel and protects the installed directory with operating
system permissions. A future signed release manifest can improve distribution
authenticity; this implementation does not claim that property.

## File classes

- `CONTROL_PLANE`: canonical RAD policy, security launcher/policy, process
  harness, CI configuration, bootstrap instructions, immutable requirements,
  authoritative decisions, generator, and security regression tests.
- `GENERATED_CONTROL_OUTPUT`: runtime adapters and generated root `CLAUDE.md`.
- `PRODUCT_WORKSPACE`: ordinary product source and tests.
- `EVIDENCE_REPORTING`: defects, adversarial reports, benchmarks, PoC reports,
  and captured evidence. Evidence is data and never grants authority.

Any nested `AGENTS.md` or `CLAUDE.md` is control material because runtimes can
consume instruction files below the project root. Runtime directories such as
`.opencode/` are protected in their entirety, including plugins, tools, commands,
formatters, language-server configuration, and MCP configuration added later.
Root runtime configuration such as `opencode.json`, `opencode.jsonc`, and
`.mcp.json` is protected as well; an untrusted project cannot introduce it after
the baseline was reviewed.

In product mode, ordinary roles cannot write either protected class. This policy
classification is consumed by the launcher/broker; classification alone is not
an operating-system filesystem boundary. Secure Mode must additionally enforce
the decision for tool calls and every subprocess descendant.

Phase 2C adds the OS boundary:

- After baseline admission, public `rad_secure.py guard --action lock` and
  `--action unlock` refuse before guard target enumeration or ACL mutation
  because no durable recovery snapshot is available. `--action verify` observes
  the effective boundary without changing it and does not claim that recovery
  data exists.
- Trusted-project launch requires `--guard-control-plane` and uses an internal
  in-process lifecycle: capture and validate every snapshot, acquire every
  target handle, apply deny ACLs, verify the boundary, run the trusted-project
  executable, then restore and verify the captured ACLs during normal cleanup.
  The same identity-bound target handle remains open from capture through
  mutation and restoration; there is no post-mutation close/reopen handoff.
  Missing, NULL and currently unsupported empty DACLs fail before mutation.
- Snapshots are process-local. Abrupt launcher termination has no exact automatic
  recovery path. A project left locked by an older RAD version without trusted
  recovery data requires an independently trusted backup or manual security
  review; RAD does not infer the original ACL by deleting matching deny ACEs.
- `install.py --harden` makes the installed authority tree mutation-denied for
  every principal (including the owning account). The target repository cannot
  modify the trusted installation, launcher, policy, verifier or baseline even
  under the same OS user. The production CLI exposes no supported unhardening
  workflow: hardening remains active, and replacement requires a separately
  reviewed trusted installation procedure. RAD must fail closed rather than
  alter that protection without trusted recovery state. Deployment keeps the
  installation outside the untrusted workspace and provisioned with operator OS
  policy.

## WSL2 secure backend (Phase 2D)

For the certified Codex WSL2 backend the authority is divided across two OS
boundaries:

```text
Windows host:  installed RAD baseline/policy/verifier (external pin, harden)
               launcher: verify -> mirror -> guard -> clean-env -> run
WSL2 SECURE DISTRO (RAD-Secure-Test):
               trusted WSL root (install, chattr -i guard, cleanup)
               non-root execution user (hostile code)
               Codex CLI (pinned Linux binary + native self-probe)
```

- The host installation stays the **authority**; the WSL copy of the project is
  a mirrored, disposable run representation, never a source of policy.
- The mirrored project's control plane is root-owned and immutable
  (`chattr +i`) inside the distro before hostile execution; the sandbox user
  cannot write, chmod, unlink or rename-over those files even though the
  workspace itself is writable.
- The distribution is kept free of personal projects and credential stores;
  Windows credentials never enter the distro (no automount, no interop).
- The launcher constructs the environment; hostile processes cannot read
  secrets they were never given, and the Windows-side RAD secrets/keys stay on
  the host.

The `mirror_tree` transfer never executes project content (tar/base64 copy) and
`wsl.exe` arguments never carry project-controlled text.

## Installation and verification

Installation is an explicit maintenance action:

```text
<absolute-trusted-python> -I -B <reviewed-RAD>/security/install.py \
  --source <absolute-release-tree> \
  --destination <absolute-new-external-directory> \
  --release-id <release-version> \
  --expected-release-sha256 <digest-from-independent-channel> \
  --authorize-maintenance
```

The source and destination must be absolute, disjoint, non-reparse paths. The
destination must not exist. The installer rejects symlinks, junctions, reparse
points, path traversal, Windows alternate data streams, device names, ambiguous
case/Unicode paths, oversized files, and a source or copied tree that differs
from the external release pin.

The installed `.rad-security-baseline.json` uses a strict schema and records the
size and SHA-256 of every control-plane and generated-control file. At launch:

1. verify the installed payload against the externally held release digest and
   expected release identifier;
2. load the strict manifest, recompute its protected-file records from the
   pinned installed payload, and require an exact match (the manifest cannot
   establish its own authority);
3. enumerate the target's protected files without following links;
4. reject missing, changed, or unexpected protected files;
5. never execute a checker from the target to establish trust.

Changing a target checker and the files it checks therefore does not change the
installed authority. A legitimate control-plane change requires maintenance
mode, review, a new release digest obtained outside the checkout, and a new
installation directory. Product reports and model claims cannot enter that
mode.
