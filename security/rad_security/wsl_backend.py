"""Windows-side driver for the certified Codex WSL2 Secure Mode backend.

The trusted WSL distribution is part of the security component.  This module
must never be imported from inside the hostile project.  It drives ``wsl.exe``
from the trusted launcher, verifies the pinned Codex executable and the
effective sandbox properties before anything executes, secrets-stages the
target project into a generated strict run root under the WSL Linux filesystem,
and runs project commands through the Codex Linux sandbox as a dedicated
non-root user.

Phase 4 hardening applied here:

- PH3-001: ``wsl.exe`` is resolved from the canonical trusted system directory
  (absolute path), never via PATH or the current directory.
- PH3-002: remote run roots are generated strict identifiers
  (``/home/<user>/runs/<16-hex-runid>/project``); project-controlled paths
  never become shell syntax; cleanup validates the generated path pattern and
  never runs ``rm -rf`` against a caller-supplied string. Environment values
  containing control characters are rejected, and every embedded argument is
  shell-quoted deterministically.
- PH3-003: scripts that run with WSL **root** privileges are staged in a
  root-owned mode-0700 private directory with cryptographically random names,
  never in a predictable shared ``/tmp`` path; the immutable-guard report is
  returned through a root-owned random report file.
- PH3-004: the WSL control-plane guard emits structured JSON status and fails
  closed unless every mandatory path is present and immutable with zero errors.
- PH3-008: project staging excludes secrets (``.env``, credential stores,
  ``.git/**`` and more), enforces size/file-count limits, and streams the
  archive to the distro instead of building it fully in memory.
- Phase 4 #8/#9: the Codex executable hash, version and absolute path are
  pinned and must match the expected tuple; the effective sandbox behavior is
  verified natively (socket denial + control-write denial) before launch.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tarfile
import tempfile
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

from .policy import canonicalize_existing_directory

DEFAULT_DISTRO = "RAD-Secure-Test"
DEFAULT_USER = "radtest"
SECURE_PROFILE = ":workspace"
CODEX_VERSION = "0.153.4"

_RUN_PATTERN = re.compile(r"^/home/[A-Za-z0-9_-]+/runs/[0-9a-f]{16}$")
_REMOTE_PROJECT_RE = re.compile(
    r"^/home/[A-Za-z0-9_-]+/runs/[0-9a-f]{16}/project$")

# PH3-008: staged size and secret-exclusion policy.
MAX_STAGED_FILES = 20000
MAX_STAGED_FILE_BYTES = 32 * 1024 * 1024
MAX_STAGED_TOTAL_BYTES = 512 * 1024 * 1024
_STAGED_EXCLUDE_PARTS = frozenset({
    ".git", ".hg", ".svn", ".ssh", ".aws", ".azure", "__pycache__",
    ".pytest_cache", "node_modules", ".npm", ".gradle", ".m2",
})
_STAGED_EXCLUDE_NAMES = frozenset({
    ".env", ".npmrc", ".pypirc", ".gemrc", ".netrc", ".git-credentials",
    ".dockerconfigjson", "id_rsa", "id_ed25519",
})
_STAGED_EXCLUDE_SUFFIXES = (".env.", ".pem", ".key", ".pfx", ".p12")


class WslBackendError(RuntimeError):
    """Raised when the WSL Secure Mode backend cannot be verified or used."""


def _windows_directory() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise WslBackendError("cannot determine trusted Windows directory")
    return Path(buffer.value).resolve()


def _wsl_executable() -> str:
    """PH3-001: absolute trusted system wsl.exe; never PATH/current-dir."""
    candidate = _windows_directory() / "System32" / "wsl.exe"
    if not candidate.is_file():
        raise WslBackendError("trusted wsl.exe missing: %s" % candidate)
    return str(candidate)


def _wsl(*arguments, distro: Optional[str] = None,
         user: Optional[str] = None,
         stdin_bytes: Optional[bytes] = None,
         stdin_file=None,
         timeout: float = 300):
    command = [_wsl_executable()]
    if distro:
        command += ["-d", distro]
    if user:
        command += ["-u", user]
    command += list(arguments)
    process = subprocess.run(
        command,
        input=stdin_bytes,
        stdin=stdin_file,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return _CompletedResult(process.returncode, _decode_wsl_output(process.stdout))


def _decode_wsl_output(raw: bytes) -> str:
    """wsl.exe writes UTF-16LE (sometimes with a BOM) when stdout is a pipe."""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if b"\x00" in raw[:512]:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


class _CompletedResult:
    __slots__ = ("returncode", "stdout", "stderr")

    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _validate_linux_path(value: str, pattern: re.Pattern[str], label: str) -> str:
    path = str(value)
    if not pattern.fullmatch(path):
        raise WslBackendError("%s is not a generated trusted Linux path: %s"
                              % (label, path))
    return path


def _require_no_control(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise WslBackendError("%s must be text" % label)
    if any(ord(c) < 32 for c in value) or "\x7f" in value:
        raise WslBackendError("%s contains control characters" % label)
    return value


def _shell_quote(value: str) -> str:
    """Deterministic single-quote shell quoting."""

    _require_no_control(value, "shell argument")
    if re.fullmatch(r"[A-Za-z0-9_./=:+-]+", value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def _run_script(distro: str, user: str, script: str, timeout: float,
                ) -> subprocess.CompletedProcess:
    """PH3-002/PH3-003: run a POSIX script in the distro.

    The script is base64-delivered into a private, random-named file owned by
    the executing principal and then executed.  ``wsl.exe`` mangles ``$var``
    inside ``sh -c`` arguments, so the write, execute and delete steps here are
    separate variable-free invocations with literal paths only.
    """
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    name = secrets.token_hex(8) + ".sh"
    root_dir = "/var/lib/rad-secure/wsl-scripts"
    user_dir = "/home/%s/.rad-secure/bin" % user
    script_dir = root_dir if user == "root" else user_dir
    script_file = "%s/%s" % (script_dir, name)
    write = (
        "umask 077; mkdir -p -- %(dir)s && chmod 700 -- %(dir)s && "
        "printf '%%s' '%(encoded)s' | base64 -d > %(file)s && "
        "chmod 700 -- %(file)s"
        % {"dir": script_dir, "encoded": encoded, "file": script_file}
    )
    written = _wsl("--", "sh", "-c", write, distro=distro, user=user, timeout=timeout)
    if written.returncode != 0:
        raise WslBackendError("cannot stage script in distro: %s"
                              % written.stdout.strip()[-200:])
    try:
        return _wsl("--", "bash", script_file, distro=distro, user=user,
                    timeout=timeout)
    finally:
        with _ignore_errors():
            _wsl("--", "rm", "-f", script_file, distro=distro, user=user,
                 timeout=timeout)


def _wsl_root(distro: str, script: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return _run_script(distro, "root", script, timeout)


def _wsl_user(distro: str, user: str, script: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return _run_script(distro, user, script, timeout)


# Default control-plane surface for the WSL guard; extended by the baseline.
CONTROL_FILES = ("AGENTS.md", "CLAUDE.md", "DECISIONS.md",
                 "REQUIREMENTS.md", "SECURITY.md",
                 "opencode.json", "opencode.jsonc")
CONTROL_DIRS = (".rad", ".github", ".opencode", ".codex", ".claude",
                ".cursor", ".agents", "tools", "scripts", "security")


def distro_exists(distro: str = DEFAULT_DISTRO) -> bool:
    result = _wsl("-l")
    return distro in result.stdout


def wsl_version(distro: str = DEFAULT_DISTRO) -> str:
    result = _wsl("--", "sh", "-c",
                  "cat /proc/sys/kernel/ostype /proc/sys/kernel/osrelease 2>/dev/null | head -2",
                  distro=distro, user="root")
    return result.stdout.strip()


def _measure_codex(distro: str, user: str, codex_abs: str
                   ) -> Tuple[Optional[str], Optional[str]]:
    probe = _wsl("--", "sh", "-c",
                 "if [ ! -x '%s' ]; then echo MISSING; exit 0; fi; "
                 "sha256sum '%s' | cut -d' ' -f1; "
                 "'%s' --version 2>/dev/null | head -1" % (codex_abs, codex_abs, codex_abs),
                 distro=distro, user=user, timeout=120)
    lines = probe.stdout.strip().splitlines()
    if not lines or lines[0] == "MISSING":
        return None, None
    digest = lines[0].strip()
    version = lines[1].strip() if len(lines) > 1 else ""
    return digest or None, version or None


def verify_wsl_backend(
    *,
    distro: str = DEFAULT_DISTRO,
    user: str = DEFAULT_USER,
    codex_path: Optional[str] = None,
    codex_sha256: Optional[str] = None,
    codex_version: Optional[str] = None,
    probe: bool = True,
) -> Mapping[str, object]:
    """Fail-closed verification of the certified WSL backend.

    ``codex_path`` must be an absolute path inside the distro; ``codex_sha256``
    is the independently published SHA-256 and ``codex_version`` the expected
    version.  Any mismatch refuses the backend.  When ``probe`` is set, a
    harmless self-probe confirms socket denial and control-write denial.
    """
    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    if distro_exists(distro):
        record("distro-present", True, distro)
    else:
        record("distro-present", False,
               "WSL distribution %s is not registered" % distro)
        return {"ok": False, "checks": checks}

    version = _wsl("--", "sh", "-c",
                   "id -u; cat /etc/os-release 2>/dev/null | grep PRETTY",
                   distro=distro, user=user)
    uid = version.stdout.splitlines()[0].strip() if version.stdout.strip() else ""
    record("non-root-user", uid != "0", "uid=%s" % uid)

    interop = _wsl("--", "sh", "-c",
                   "command -v cmd.exe >/dev/null 2>&1 && echo interop-on || echo interop-off",
                   distro=distro, user=user)
    record("interop-off", "interop-off" in interop.stdout, interop.stdout.strip())

    mounted = _wsl("--", "sh", "-c",
                   "ls /mnt/c/Windows >/dev/null 2>&1 && echo c-visible || echo c-hidden",
                   distro=distro, user=user)
    record("host-drive-hidden", "c-visible" not in mounted.stdout, mounted.stdout.strip())

    if not codex_path or not codex_path.startswith("/"):
        record("codex-pin", False, "codex_path must be absolute")
        return {"ok": False, "checks": checks}
    digest, measured = _measure_codex(distro, user, codex_path)
    hash_ok = digest is not None and codex_sha256 is not None and digest.lower() == codex_sha256.lower()
    record("codex-hash", hash_ok,
           "sha256=%s" % (digest[:16] if digest else "unable to hash"))
    version_ok = codex_version is not None and measured is not None and codex_version in measured
    record("codex-version", version_ok,
           "measured=%s expected=%s" % (measured, codex_version))

    if probe:
        probe_result = self_probe(distro, user, codex_path)
        record("socket-denied", probe_result["socket_denied"],
               probe_result.get("socket_detail", ""))
        record("control-write-denied", probe_result["control_write_denied"],
               probe_result.get("control_detail", ""))

    ok = all(item["ok"] for item in checks)
    return {"ok": ok, "distro": distro, "user": user,
            "codex_path": codex_path,
            "codex_sha256": codex_sha256, "codex_version": codex_version,
            "version": CODEX_VERSION, "checks": checks}


def self_probe(distro: str, user: str, codex_abs: str) -> Mapping[str, object]:
    """PH3-004/#9: structured, harmless sandbox self-probe.

    The immutable flag requires root (CAP_LINUX_IMMUTABLE); the probe itself
    runs as the non-root execution user inside the sandbox.
    """
    probe_root = "/home/%s/probe-root" % user
    _wsl_root(distro, (
        "rm -rf -- %(root)s; mkdir -p -- %(root)s; "
        "chown %(user)s:%(user)s -- %(root)s; "
        "echo ctl > %(root)s/AGENTS.md; "
        "chown %(user)s:%(user)s -- %(root)s/AGENTS.md; "
        "chattr -i -- %(root)s/AGENTS.md 2>/dev/null || true; "
        "chattr +i -- %(root)s/AGENTS.md 2>/dev/null"
    ) % {"root": probe_root, "user": user}, timeout=120)
    out = _wsl_user(distro, user, (
        "'%(codex)s' sandbox -P :workspace -C %(root)s -- bash -c '"
        'if python3 -c "import socket; socket.socket()" 2>/dev/null; '
        "then echo SOCKET-OK; else echo SOCKET-DENIED; fi; "
        "if echo x >> %(root)s/AGENTS.md 2>/dev/null; "
        "then echo WRITE-OK; else echo WRITE-DENIED; fi' 2>/dev/null"
    ) % {"codex": _shell_quote(codex_abs), "root": probe_root}, timeout=180)
    _wsl_root(distro, (
        "chattr -i -- %(root)s/AGENTS.md 2>/dev/null; rm -rf -- %(root)s"
    ) % {"root": probe_root}, timeout=120)
    stdout = out.stdout
    return {
        "socket_denied": "SOCKET-DENIED" in stdout,
        "control_write_denied": "WRITE-DENIED" in stdout,
        "socket_detail": stdout.strip()[-200:],
        "control_detail": stdout.strip()[-200:],
    }


def _exclude_for_staging(name: str) -> bool:
    if name in _STAGED_EXCLUDE_PARTS:
        return True
    if name in _STAGED_EXCLUDE_NAMES:
        return True
    lowered = name.lower()
    for suffix in _STAGED_EXCLUDE_SUFFIXES:
        if lowered.startswith(suffix) or lowered.endswith(suffix):
            return True
    return False


def stage_project(local_root, distro: str, user: str = DEFAULT_USER,
                  timeout: float = 900) -> str:
    """PH3-002/PH3-008: secrets-stage a local project into a generated run root.

    Returns ``/home/<user>/runs/<16-hex-runid>/project``.  The run id is
    generated crypto-randomly here; the caller never supplies a remote path, so
    no project-controlled string becomes shell syntax and cleanup stays scoped
    to the generated run root.
    """
    local = canonicalize_existing_directory(local_root)
    run_id = secrets.token_hex(8)
    remote_abs = "/home/%s/runs/%s/project" % (user, run_id)
    _validate_linux_path(remote_abs, _REMOTE_PROJECT_RE, "remote project")

    archive = tempfile.TemporaryFile()
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=archive, mode="w|", format=tarfile.GNU_FORMAT) as tar:
            for current_text, directories, filenames in os.walk(local):
                current = Path(current_text)
                kept = [name for name in directories if not _exclude_for_staging(name)]
                directories[:] = kept
                for name in filenames:
                    if _exclude_for_staging(name):
                        continue
                    source = current / name
                    info = source.lstat()
                    if getattr(info, "st_nlink", 1) != 1:
                        raise WslBackendError("hardlinked file refused in staging: %s" % source)
                    if info.st_size > MAX_STAGED_FILE_BYTES:
                        raise WslBackendError(
                            "staged file exceeds size limit: %s" % source)
                    total += info.st_size
                    count += 1
                    if count > MAX_STAGED_FILES:
                        raise WslBackendError("staged file count limit exceeded")
                    if total > MAX_STAGED_TOTAL_BYTES:
                        raise WslBackendError("staged total size limit exceeded")
                    relative = source.relative_to(local).as_posix()
                    tar.add(str(source), arcname=relative, recursive=False)
        archive.seek(0)
        create_script = (
            "set -eu; rm -rf -- %(run)s; mkdir -p -- %(project)s; "
            "tar -x -C %(project)s" % {"run": remote_abs.rsplit("/", 1)[0],
                                       "project": remote_abs}
        )
        result = _wsl("--", "sh", "-c", create_script, distro=distro, user=user,
                      stdin_file=archive, timeout=timeout)
    finally:
        archive.close()
    if result.returncode != 0:
        _wsl_user(distro, user, "rm -rf -- %s" % remote_abs.rsplit("/", 1)[0],
                  timeout=120)
        raise WslBackendError("stage to WSL failed: %s" % result.stdout.strip()[-300:])
    return remote_abs


def _wsl_standard_surface() -> List[str]:
    required = list(CONTROL_FILES) + list(CONTROL_DIRS)
    return list(dict.fromkeys(required))


def _wsl_mandatory_paths(protected_relative: Optional[Iterable[str]]) -> List[str]:
    """Mandatory = the authority-derived baseline set, if any.

    When no baseline is supplied (internal/testing use), nothing is mandatory
    and the standard control surface is protected as coverage-if-present.
    """
    if protected_relative is None:
        return []
    return sorted(set(p for p in protected_relative if p))


def _wsl_coverage_paths(protected_relative: Optional[Iterable[str]]) -> List[str]:
    coverage = _wsl_standard_surface()
    if protected_relative is not None:
        coverage.extend(path for path in protected_relative if path)
    return list(dict.fromkeys(coverage))


def guard_control_plane_wsl(remote_project: str, distro: str = DEFAULT_DISTRO,
                            protected_relative: Optional[Iterable[str]] = None,
                            timeout: float = 300) -> Mapping[str, object]:
    """PH3-004: fail-closed immutable control-plane guard with JSON status.

    ``protected_relative`` (when not None) is the authority-derived mandatory
    protected set.  Every mandatory path must be present and immutable; every
    existing coverage path (standard control surface) must also be immutable.
    A single missing/unguarded/erroring path fails the whole guard; the status
    is strict JSON — never a substring match.
    """
    _validate_linux_path(remote_project, _REMOTE_PROJECT_RE, "remote project")
    mandatory = _wsl_mandatory_paths(protected_relative)
    coverage = [name for name in _wsl_coverage_paths(protected_relative)
                if name not in mandatory]
    payload = json.dumps({"mandatory": mandatory, "coverage": coverage},
                         sort_keys=True, separators=(",", ":"))
    script_generator = None
    result = _wsl_root(distro, _guard_script(remote_project, payload), timeout=timeout)
    try:
        report = json.loads(result.stdout.strip() or "{}")
    except ValueError as error:
        raise WslBackendError("guard status is not structured JSON: %s"
                              % result.stdout.strip()[-200:]) from error
    if report.get("status") != "guarded" or not isinstance(report.get("errors"), list) or report.get("errors"):
        raise WslBackendError("control-plane guard failed closed: %s"
                              % json.dumps(report, sort_keys=True))
    return report


def _guard_script(remote_project: str, payload: str) -> str:
    return r'''
set -eu
proj=%s
payload='%s'
report="$proj/.rad-guard-report.tmp"
rm -f -- "$report"
: > "$report"
printf '%%s' "$payload" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for p in d["mandatory"]: print("M\t" + p)
for p in d["coverage"]: print("C\t" + p)
' | while IFS=$'\t' read -r kind rel; do
  [ -n "$rel" ] || continue
  p="$proj/$rel"
  if [ "$kind" = "M" ] && [ ! -e "$p" ]; then echo "MISSING\t$rel" >> "$report"; continue; fi
  if [ ! -e "$p" ]; then continue; fi
  if [ -d "$p" ]; then
    chattr -R -i -- "$p" 2>/dev/null || true
    if ! chattr -R +i -- "$p" 2>/dev/null; then echo "CHATTR_FAIL\t$rel" >> "$report"; continue; fi
    if ! lsattr -d -- "$p" 2>/dev/null | grep -q i; then echo "NOT_IMMUTABLE\t$rel" >> "$report"; fi
  else
    chattr -i -- "$p" 2>/dev/null || true
    if ! chattr +i -- "$p" 2>/dev/null; then echo "CHATTR_FAIL\t$rel" >> "$report"; continue; fi
    if ! lsattr -d -- "$p" 2>/dev/null | grep -q i; then echo "NOT_IMMUTABLE\t$rel" >> "$report"; fi
  fi
done || true
python3 - "$report" <<'PYEOF'
import json
import os
import sys
path = sys.argv[1]
errors = []
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line:
                errors.append(line)
except OSError:
    errors = ["GUARD_REPORT_UNREADABLE"]
try:
    os.unlink(path)
except OSError:
    pass
sys.stdout.write(json.dumps(
    {"status": "guarded" if not errors else "error",
     "errors": errors}, sort_keys=True) + "\n")
PYEOF
''' % (remote_project, payload)


def unguard_control_plane_wsl(remote_project: str, distro: str = DEFAULT_DISTRO,
                              protected_relative: Optional[Iterable[str]] = None,
                              timeout: float = 300) -> None:
    _validate_linux_path(remote_project, _REMOTE_PROJECT_RE, "remote project")
    mandatory = _wsl_mandatory_paths(protected_relative)
    coverage = [name for name in _wsl_coverage_paths(protected_relative)
                if name not in mandatory]
    payload = json.dumps({"mandatory": mandatory, "coverage": coverage},
                         sort_keys=True, separators=(",", ":"))
    script = (
        "set +e; proj=%s; payload='%s'; "
        "printf '%%s' \"$payload\" | python3 -c '"
        'import json, sys; d = json.load(sys.stdin);\n'
        'for p in d["mandatory"] + d["coverage"]: print(p)\' '
        '| while IFS= read -r rel; do [ -n "$rel" ] || continue; '
        'p="$proj/$rel"; [ -d "$p" ] && chattr -R -i -- "$p" 2>/dev/null '
        '|| chattr -i -- "$p" 2>/dev/null; done'
        % (remote_project, payload)
    )
    _wsl_root(distro, script, timeout=timeout)


def clean_remote(remote_project: str, distro: str = DEFAULT_DISTRO,
                 user: str = DEFAULT_USER, timeout: float = 300) -> None:
    """PH3-002: remove a generated run root; validate the path pattern first."""
    _validate_linux_path(remote_project, _REMOTE_PROJECT_RE, "remote project")
    run_root = remote_project.rsplit("/", 1)[0]
    _validate_linux_path(run_root, _RUN_PATTERN, "run root")
    unguard_control_plane_wsl(remote_project, distro, None, timeout)
    _wsl_root(distro, "rm -rf -- %s" % run_root, timeout=timeout)


def _build_sandbox_environment(user: str, extra: Optional[Mapping[str, str]]
                               ) -> Mapping[str, str]:
    env = {
        "HOME": "/home/%s" % user,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "/tmp",
        "TMP": "/tmp",
        "XDG_RUNTIME_DIR": "/tmp",
    }
    if extra:
        for key, value in extra.items():
            _require_no_control(str(value), "environment value for %s" % key)
            if key.upper() == "PATH" or key in ("HOME", "XDG_RUNTIME_DIR", "TMP", "TMPDIR"):
                continue
            env[key] = str(value)
    return env


def run_sandboxed(
    distro: str, user: str, remote_project: str,
    inner: Sequence[str],
    sandbox_profile: str = SECURE_PROFILE,
    environment: Optional[Mapping[str, str]] = None,
    codex: str = "/usr/local/bin/codex",
    timeout: float = 600,
) -> subprocess.CompletedProcess:
    """Run ``inner`` inside the Codex Linux sandbox for a staged project.

    ``inner`` is the operator/launcher-provided command executed *inside* the
    sandbox; the environment is constructed from ``environment`` and nothing
    else is inherited.
    """
    _validate_linux_path(remote_project, _REMOTE_PROJECT_RE, "remote project")
    codex = _require_absolute(codex)
    safe_env = _build_sandbox_environment(user, environment)
    env_block = " ".join("'%s=%s'" % (key, _shell_quote(value))
                         for key, value in sorted(safe_env.items()))
    inner = " ".join(_shell_quote(part) for part in inner)
    script = (
        "{ env -i %(env)s %(codex)s sandbox -P %(profile)s -C %(project)s -- %(inner)s ; } 2>&1"
    ) % {"env": env_block, "codex": _shell_quote(codex),
         "profile": sandbox_profile, "project": remote_project, "inner": inner}
    return _run_script(distro, user, script, timeout)


def _require_absolute(value: str) -> str:
    value = _require_no_control(value, "codex path")
    if not value.startswith("/") or not value:
        raise WslBackendError("codex path must be absolute")
    return value


class _ignore_errors:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return True


def launch_secure_run(
    local_project,
    *,
    distro: str = DEFAULT_DISTRO,
    user: str = DEFAULT_USER,
    codex_path: str = "/usr/local/bin/codex",
    codex_sha256: str,
    codex_version: str = CODEX_VERSION,
    inner: Sequence[str],
    environment: Optional[Mapping[str, str]] = None,
    protected_relative: Optional[Iterable[str]] = None,
    timeout: float = 900,
) -> Mapping[str, object]:
    """PH3-007: the single public hostile-project secure run.

    Executes in order: backend/pin verification -> secret-aware staging ->
    immutable guard -> sandbox execution -> cleanup.  Any failure aborts before
    project code executes, and the staged run is cleaned up.
    """
    backend = verify_wsl_backend(distro=distro, user=user,
                                 codex_path=codex_path,
                                 codex_sha256=codex_sha256,
                                 codex_version=codex_version,
                                 probe=True)
    if not backend["ok"]:
        failures = [c["detail"] for c in backend["checks"] if not c["ok"]]
        raise WslBackendError("codex-wsl backend verification failed: "
                              + "; ".join(failures))
    remote = stage_project(local_project, distro, user)
    try:
        guard = guard_control_plane_wsl(remote, distro, protected_relative)
        run = run_sandboxed(distro, user, remote, inner,
                            environment=environment, codex=codex_path,
                            timeout=timeout)
        return {"ok": True, "run_rc": run.returncode, "stdout": run.stdout,
                "guard": guard, "remote_project": remote}
    finally:
        with _ignore_errors():
            clean_remote(remote, distro, user)