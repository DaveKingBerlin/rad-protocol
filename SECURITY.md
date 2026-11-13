# Security Policy

## Phase 2D status

**Codex WSL2 is the first certified hostile-project Secure Mode backend.**

- Codex CLI 0.153.4 inside the dedicated hardened `RAD-Secure-Test` WSL2
  distribution is **SUPPORTED** for hostile-project Secure Mode: the Linux
  bubblewrap sandbox denies raw sockets entirely (private network namespace,
  no routes, DNS blocked), the project runs in the Linux filesystem as a
  non-root user, Windows interop is disabled and drives are not mounted, and
  the repository control plane is immutable at the OS layer (root-owned
  `chattr +i`).
- **Codex native Windows stays TRUSTED-PROJECT ONLY** (host loopback remained
  reachable in the Phase-2C native probes). A platform/runtime/version is part
  of any certification; "Codex" is never generically secure.
- OpenCode, Claude Code and Cursor remain TRUSTED-PROJECT ONLY.
- SEC-001 is **FIXED** (at least one technically verified hostile-project
  backend + launcher refuses uncertified/uncertified-in-combination backend/
  platform). SEC-002 and AGT-001 remain fixed; all committed security
  regression tests pass.

See [Secure Mode](docs/SECURE_MODE.md), the
[runtime matrix](docs/RUNTIME_SUPPORT.md) and the
[trusted installation requirements](docs/TRUSTED_BASELINE.md). Native
certification evidence is carried by the permanent suites
`tests/security/test_wsl_secure_backend.py` (WSL backend) and
`tests/security/test_control_plane_guard.py` (windows guard); run them on a
host with the `RAD-Secure-Test` distribution present.

The launcher refuses uncertified backend/platform combinations. Job Object
teardown and the independent baseline/structured file broker have regression
tests. A passing refusal test is not a passing sandbox test.

## Phase 4 (security remediation)

Phase 4 remediated the independent Phase 3 findings PH3-001..PH3-009:

- **PH3-001** executable shadowing: `wsl.exe`/`icacls.exe`/`powershell.exe`
  are resolved only from `%SystemRoot%\System32`.
- **PH3-002/003** shell interpolation and root temp scripts: strict generated
  run roots, deterministic quoting, root-private 0700 script staging.
- **PH3-004** WSL guard fail-closed via structured JSON with per-path
  immutable verification.
- **PH3-005** Windows append bypass closed (deny `AD`/`WEA`); WRITE_DAC/Owner
  remain the documented separate-principal residual.
- **PH3-006** protected leaves derived from the verified baseline (incl.
  nested leaves below product directories).
- **PH3-007** one public secure-launch path (`launch --runtime codex-wsl`
  → verify/pin → stage → guard → sandbox → cleanup); helper functions are wired
  into it.
- **PH3-008** secret-aware staging (`.env`, credentials, `.git/**` excluded;
  size limits; streamed).
- **PH3-009** exact restore and verification of the captured Owner, Group and
  DACL SDDL, including ACE order/flags, plus the full 16-bit control word
  returned with that requested descriptor. The SACL is not part of this
  snapshot and is not written by the guard; this is not a byte-for-byte binary
  descriptor guarantee.
- Guardian hardens malformed UTF-8 control input (safe failure, no Job teardown).

### Decision PH5-ACL-001 — Windows ACL restore contract (2026-11-13)

This decision clarifies the Windows Trusted Project guard contract. It does not
replace the historical Phase 5 acceptance criterion. For a regular,
successfully completed in-process session, every security component RAD changes
must be restored and verified exactly; components RAD does not request for
mutation must not be changed as a side effect. Independent proof of SACL
identity and byte-for-byte identity of the complete binary descriptor remains
outside the current evidence and is not claimed.

The Windows guard adds its deny ACE through handle-based `SetSecurityInfo` with
`MAXIMUM_ALLOWED`, which the API documents as suppressing descendant ACE
propagation. On restore, captured DACLs with `SE_DACL_AUTO_INHERITED` use that
handle-based API. Captured DACLs without that bit use the older
`SetFileSecurityW` path API because the handle-based setter normalizes them to
the current inheritance model. That path write runs while the target and its
relevant ancestors are pinned by identity-checked handles, and the resulting
Owner/Group/DACL SDDL and the returned 16-bit control word are read back and
compared. All API failures or comparison mismatches fail closed. No SACL,
mandatory-label or resource-attribute write is requested; those SACL components
and the resource-manager control byte are not part of this snapshot.

All target handles are acquired before the first ACL mutation. The same
identity-checked `MAXIMUM_ALLOWED` target handle remains open from snapshot
capture through deny mutation, rollback or verified restore. This closes the
former post-mutation close/reopen gap; relevant ancestor handles remain pinned
for the AI-clear path operation.

A Windows lock is refused before its first ACL mutation if any captured
descriptor has a missing or NULL DACL. A valid empty DACL is also refused: exact
recovery for that state has not been established on the supported NTFS restore
paths. Recovery snapshots exist only in the live guard process. The normal
trusted-project launcher restores and verifies them in-process when its cleanup
runs, but there is no durable crash-recovery journal. Public standalone
`guard --action lock` and `guard --action unlock` therefore refuse before
guard target enumeration or ACL mutation, after baseline admission.
`guard --action verify` remains read-only;
it reports whether the boundary appears effective, not whether a trusted
snapshot exists or recovery is possible. Projects left locked by an older RAD
version require an independently trusted backup or manual security review; RAD
does not guess an original ACL or claim automatic recovery.

This Windows guard is a Trusted Project defense-in-depth control. Runtime code
still executes as the project owner, so it is not a hostile-agent isolation
boundary. The certified WSL2 backend uses separate guest enforcement; its
Hostile Project guarantees do not apply to native Windows Trusted Project mode.

Codex WSL2 remains **SUPPORTED only** with the pinned tuple (Codex 0.153.4
linux-x64, SHA-256 enforced, distro `RAD-Secure-Test`); the launcher refuses
startup without the independent binary pin. Each PH3 remediation is covered
by a named native regression in `tests/security/test_control_plane_guard.py`
and `tests/security/test_wsl_secure_backend.py`.

### Certification vs CI

Hosted CI cannot run the WSL certified backend (the dedicated distribution is
absent), so the WSL tests **skip** there and are re-run natively at release
time on a host with `RAD-Secure-Test` present. A skip is not a pass. GitHub
Actions runs the portable security regressions (`ubuntu-latest`) and the
Windows-native regressions (`windows-latest`); the workflow file itself is
validated for YAML syntax on every run.

## Reporting a vulnerability

Please report security vulnerabilities privately using GitHub Private
Vulnerability Reporting.

Please do not place exploit details, credentials, private source documents
or sensitive PoC data in public issues.

## Autonomous-agent safety

RAD projects should:

- keep secrets outside project artifacts
- gitignore `.env` and generated browser profiles
- require explicit policy for paid/external calls
- prefer deterministic mocks for default tests
- review sandbox and effective permissions during preflight
- treat source documents and provider responses as untrusted data
- retain independent QA and adversarial validation
