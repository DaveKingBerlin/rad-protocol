# RAD Secure Mode: implementation and limitations

**One backend is certified in this revision: Codex CLI 0.153.4 inside the
hardened dedicated WSL2 distribution `RAD-Secure-Test`.** The installed
launcher admits that backend only after an external pin and a native
self-probe, and refuses every other backend/platform combination before
runtime startup. It never falls back to a less restricted agent.

## Trust boundary and boot

```text
Windows host
  -> trusted RAD launcher (external pin + baseline verify)
  -> WSL2 SECURE DISTRO (RAD-Secure-Test, NAT mode)
       -> Codex CLI (pinned linux binary)
       -> Codex Linux sandbox (bubblewrap)
       -> UNTRUSTED PROJECT (Linux filesystem, non-root user)
```

The target project never gets access to Windows host files, executables,
credentials, localhost services or private network services; the dedicated WSL
distribution is itself a security component (kept free of personal data and
secrets, automount/interop disabled).

For the certified run the launcher:

1. verifies the installed payload against the external pin and the target
   baseline;
2. verifies the WSL backend natively: distro present, non-root user, interop
   off, host drives hidden, pinned Codex present, plus a sandbox self-probe
   (socket denial and control-write denial) — any failed check refuses the run;
3. mirrors the target project into the WSL Linux filesystem;
4. applies the immutable control-plane guard as root (`chattr +i`);
5. constructs a clean allowlist environment (no inherited credentials);
6. runs project commands through `codex sandbox -P :workspace` as the non-root
   sandbox user;
7. restores the guard and discards the mirrored run directory.

`wsl.exe` arguments never carry project-controlled text; scripts are delivered
as base64 into temporary files to avoid command-line quoting attacks.

## Certified sandbox properties (natively probed)

- **Network:** raw `socket()` (TCP/UDP, IPv4/IPv6) is denied with `EPERM`
  inside the sandbox; a private network namespace with no ethernet interface
  and no default route is used; DNS resolution is blocked. There is no
  reachable Windows-host gateway, Windows-hostname, LAN, RFC1918 or Internet
  destination from hostile execution, for the command and for every descendant.
- **Filesystem:** `/mnt/c`, `/mnt/d`, Windows user profile and
  Windows-mounted resources are not present; hostile writes outside the
  workspace are read-only; `/etc/shadow` and `/root` are denied.
- **Interop:** `cmd.exe`, `powershell.exe`, `pwsh.exe`, `explorer.exe`,
  `wsl.exe` and Windows executables are unavailable (interop disabled, no
  DrvFs mount).
- **Credentials:** the run environment is constructed (allowlist only); the
  clean distribution contains no SSH/AWS/Git/cloud/package credential stores;
  the Codex CLI is pinned by hash.
- **Control plane:** control files/dirs are root-owned and immutable
  (`chattr +i`); write, chmod, unlink, rename-over, symlink-over and create-in
  attempts inside the sandbox all fail with `EACCES`/`EPERM` regardless of
  process depth or language, while ordinary product files stay writable.

## Loopback interpretation

The Windows failure was dangerous because hostile code shared the host's
Windows loopback security domain. Inside WSL2 NAT, `127.0.0.1` refers only to
the guest environment, and the certified sandbox denies `socket()` entirely,
so no guest or host loopback service is reachable at all. Certification does
not depend on denying a numeric address; it depends on hostile code not
reaching any unauthorized service or network security domain, which holds.

## Commands

Use canonical absolute paths; these are placeholders, not runnable commands:

```text
<absolute-python> -I -B <installed-RAD>/security/rad_secure.py capabilities
<absolute-python> -I -B <installed-RAD>/security/rad_secure.py verify --project <absolute-project> --release-sha256 <external-pin>
<absolute-python> -I -B <installed-RAD>/security/rad_secure.py launch --runtime codex-wsl --project <absolute-project> --release-sha256 <external-pin>
```

`launch --runtime codex-wsl` runs the full backend verification and reports the
admission decision. Hostile project execution is performed by the certified
executor and covered by the WSL regression suite; uncertified runtimes
(`codex`, `opencode`, `claude`, `cursor`) are refused before startup.

`read` and `write` additionally require `--role` and `--path`. `write` receives
at most 2 MiB from stdin. Reads are bounded and handle-based. Windows writes use
the same verified exclusive file handle while ancestor directory handles prevent
replacement. Control writes are denied before opening files. There is no
maintenance role/override in this product API. Existing runtimes are **not yet
integrated with this broker**. It does not constrain their direct tools.
Product writes are not transactional: interruption may leave a partial write.

## Control-plane guard (`guard`)

`rad_secure.py guard --action lock|verify|unlock` applies a reversible
Windows ACL boundary over the repository control plane (`.rad/**`, adapters,
`AGENTS.md`, generator, governance/decision records and every other classified
control or generated-output path). While locked, **any** process — shell, test
framework, Python/Node/PowerShell, plugin, formatter, MCP server, direct
filesystem API, child, grandchild — receives `PermissionError` from the OS for
write, truncate, delete, rename-over and create-in-control operations,
independent of model instructions or tool permissions. The repository root gets
a name-entry deny so root-level control files cannot be deleted or renamed over;
collateral is that top-level create/rename/delete is also denied during a
guarded session (content edits inside product subdirectories stay writable).
`verify` only observes the effective boundary; `unlock` restores the prior ACLs.

Trusted-project launch (`launch --mode trusted-project`) now **requires**
`--guard-control-plane`; a runtime process starts only after the control plane
is OS-locked and shown to be locked. This binds every descendant of the runtime
to the control-plane boundary at the OS layer.

`install.py --harden` additionally makes an installed authority tree (launcher,
policy, baseline, verifier, process state) mutation-denied for every principal,
including the owning account, so the target repository cannot modify the trusted
installation even under the same OS user; maintenance deliberately unhardens
before placing a new release. In deployment the installed tree remains protected
outside the untrusted workspace and by OS policy for the operator principal.

The guard is defense-in-depth. A same-account process that owns the files
retains the OS owner's right to rewrite the DACL; closing that residual requires
running untrusted runtime code under a different, non-owning principal (a
certified backend requirement).

## Filesystem classes

| Class | Implemented behavior |
|---|---|
| READABLE PROJECT DATA | Bounded reads; no command or configuration evaluation |
| WRITABLE PRODUCT WORKSPACE | Windows broker (product mode); WSL sandbox workspace (secure mode) |
| RAD CONTROL PLANE | Broker denies writes; baseline detects mutation; WSL runtime makes control files immutable (`chattr +i`); Windows session guard for trusted runs |
| HOST / EXTERNAL FILESYSTEM | No broker absolute targets; WSL: no host drives/step-in; no secure runtime for other backends |

Links, junctions, reparse points, hardlinks, device/ADS/short-name paths,
unexpected protected files and oversized input fail closed. No sanitized staging
copy is created. Project extension discovery is prevented by refusing runtime
startup. This is **not** proof that managed OpenCode config or `--pure` suppresses
every project extension. A future staging backend needs race-safe copy tests.

## Network and credentials

Policy names: NO NETWORK (default), LOOPBACK-ONLY, EXPLICITLY APPROVED
DESTINATIONS, UNRESTRICTED TRUSTED MODE. LOOPBACK-ONLY and EXPLICITLY
APPROVED DESTINATIONS have no enabled secure backend yet; the fourth is never
accepted as a Secure Mode policy. The certified Codex WSL2 backend enforces the
**NO NETWORK** default technically (socket creation denied; no host/LAN/Internet
reachable); it does not offer LOOPBACK-ONLY today.

Native Windows Codex 0.154.0 evidence (Phase 2B/2C) remains valid for that
platform: the `:read-only` profile blocks project writes and external file
reads/writes, but a loopback sentinel (127.0.0.1 and ::1) was reachable from raw
Python sockets in every CLI-exercisable sandbox mode, including
`--sandbox-state-disable-network` and `features.network_proxy` with an empty
domain map. Native Windows Codex therefore cannot demonstrate `NO NETWORK`
including loopback and stays `PARTIALLY VERIFIED` / TRUSTED-PROJECT ONLY; the
launcher refuses it for hostile-project Secure Mode.

The launcher constructs a minimal environment. It never copies provider/cloud/
registry keys, SSH agents, PATH, NODE_OPTIONS or PYTHONPATH from the caller.
Runtime paths are absolute and hash-pinned, never resolved from the project.
Environment stripping alone does not prevent credential reads from disk.

## Explicit trusted-project compatibility

Existing direct runtime integrations remain available for already trusted
repositories. The separate compatibility route requires all of:

```text
--mode trusted-project --acknowledge-trusted-project
--network "UNRESTRICTED TRUSTED MODE"
--runtime-executable <absolute-runtime> --runtime-sha256 <independent-runtime-pin>
--guard-control-plane
```

It warns, passes no arbitrary runtime arguments and strips inherited credentials,
and it now OS-locks the repository control plane for the session. It does **not**
isolate hostile code, prevent extension startup or deny credential reads from
disk. Direct runtime startup also remains available when authentication
requires inherited configuration, with the same TRUSTED-PROJECT ONLY limitation.

## Maintenance and deployment

See `TRUSTED_BASELINE.md`. Maintenance is an explicit operator action: review
canonical/verification changes, authorize regeneration, test, obtain a new
external pin, install in a new directory and switch only after review. Reports,
model responses and resume state cannot perform that transition. `DECISIONS.md`
is protected governance, not a means of granting executable permission.

Before enabling a runtime backend, deployment must protect installation/state
from all target processes and establish non-overridable filesystem, network,
process and credential controls **before** runtime startup. A path check does not
install OS policy. No administrator account, firewall rule, machine-wide policy
or signing infrastructure was created by this remediation.

## Enforcement accounting

- RAD enforced: external digest, strict manifest/path/role checks, unsupported
  runtime refusal, explicit compatibility-mode selection, reversible
  control-plane guard, hardened installation, guard-bound trusted launch,
  WSL-backend verification and admission.
- OS enforced and tested: Windows Job ownership, suspended assignment,
  kill-on-close, structured handle/link/directory-sharing protections, ACL
  control-plane denial for every descendant process; WSL: private netns +
  `socket()` denial, immutable root-owned control plane, non-root host-less
  isolation.
- User dependent: trusted release/pin acquisition, protected installation,
  explicit maintenance and trusted-project execution, out-of-band authenticated
  unlock for a stale guard, provisioning of the clean dedicated WSL distro.
- Unverified: full runtime extension suppression for non-WSL backends, all
  runtime edit tools for non-certified backends, destination-approval modes,
  LOOPBACK-ONLY/EXPLICITLY-APPROVED network policies, live model-session
  executor end-to-end (requires credentials).
- Instruction-only: legacy role prompts; not Secure Mode guarantees.
