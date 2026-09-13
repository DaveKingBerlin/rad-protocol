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
- **PH3-009** exact ACL restore from SDDL snapshots.
- Guardian hardens malformed UTF-8 control input (safe failure, no Job teardown).

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
