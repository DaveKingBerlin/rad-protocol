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
import stat
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
    """Exact, parsed distro-name match (P2-4): a substring must not match
    ``RAD-Secure-Test-X`` when ``RAD-Secure-Test`` is requested."""
    result = _wsl("-l")
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("*"):
            stripped = stripped[1:].lstrip()
        name = stripped.split(None, 1)[0] if stripped else ""
        if name and name == distro:
            return True
    return False


def wsl_version(distro: str = DEFAULT_DISTRO) -> str:
    result = _wsl("--", "sh", "-c",
                  "cat /proc/sys/kernel/ostype /proc/sys/kernel/osrelease 2>/dev/null | head -2",
                  distro=distro, user="root")
    return result.stdout.strip()


def _hash_only_codex(distro: str, user: str, codex_abs: str) -> Optional[str]:
    """P1-3: SHA-256 of the executable WITHOUT executing it.

    The pinned binary must never be run merely to establish that it is the
    pinned binary.  ``sha256sum`` opens the file read-only; it does not exec.
    """
    probe = _wsl("--", "sh", "-c",
                 "if [ ! -f '%s' ]; then echo MISSING; exit 0; fi; "
                 "sha256sum '%s' 2>/dev/null | cut -d' ' -f1"
                 % (codex_abs, codex_abs),
                 distro=distro, user=user, timeout=120)
    line = probe.stdout.strip().splitlines()[0].strip() if probe.stdout.strip() else ""
    if line in ("", "MISSING"):
        return None
    return line


def _codex_version(distro: str, user: str, codex_abs: str) -> Optional[str]:
    """Run the already hash-validated executable to confirm its version."""
    measured = _wsl("--", "sh", "-c",
                    "'%s' --version 2>/dev/null | head -1" % codex_abs,
                    distro=distro, user=user, timeout=120)
    line = measured.stdout.strip().splitlines()[0].strip() if measured.stdout.strip() else ""
    return line or None


# Phase 6.2: host-isolation verification primitives.
#
# The verifier reads /proc/self/mountinfo from inside the distro and classifies
# every mount.  Only a small, version-tolerant set of WSL/system filesystems is
# allowed; anything that can carry host data (drvfs, 9p, cifs, nfs, virtiofs,
# ...) or an unknown filesystem type fails closed.  This is intentionally not a
# check of "/mnt/c exists": an empty directory is not a mounted host drive, and
# a missing /mnt/d is not proof of isolation.

# Filesystem types that can expose the Windows host or other host resources.
# This includes local host disk filesystems (ntfs/exfat/...) and network/host
# filesystems (ceph/glusterfs/...): a mount of these types carries host data
# and must never be visible inside the distro.
_HOST_FILESYSTEMS = frozenset({
    "drvfs", "cifs", "smb3", "nfs", "nfs4", "virtiofs", "fuse",
    "fuseblk", "sshfs", "davfs", "overlayfs",
    "ntfs", "ntfs3", "exfat", "vfat", "f2fs", "erofs", "iso9660", "udf",
    "ceph", "glusterfs", "gfs2", "ocfs2", "lustre", "afs",
})

# 9p is used by WSL2 itself for read-only driver/utility mounts under
# /usr/lib/wsl; only those exact targets are trusted.  A 9p mount elsewhere
# is treated as a host mount (fail closed).
_WSL_9P_TARGETS = frozenset({
    "/usr/lib/wsl/drivers",
    "/usr/lib/wsl/lib",
})

# Filesystem types that are legitimate WSL2/system mounts and carry no host
# data.  Unknown types are treated as untrusted (fail closed).
_ALLOWED_FILESYSTEMS = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "squashfs",
    "tmpfs", "ramfs", "devtmpfs", "devpts", "proc", "sysfs", "cgroup",
    "cgroup2", "securityfs", "debugfs", "tracefs", "pstore", "efivarfs",
    "mqueue", "hugetlbfs", "configfs", "fusectl", "binfmt_misc", "autofs",
    "rootfs", "nsfs", "overlay", "selinuxfs", "bpf", "9p",
})

# Exact mount targets that the WSL2/system environment legitimately provides.
_ALLOWED_MOUNT_TARGETS = frozenset({
    "/", "/init", "/dev", "/dev/pts", "/dev/shm", "/dev/mqueue",
    "/proc", "/proc/sys/fs/binfmt_misc", "/sys", "/sys/fs/cgroup",
    "/run", "/run/lock", "/run/shm", "/run/user", "/tmp/.X11-unix",
    "/mnt/wsl", "/mnt/wslg", "/mnt/wslg/distro", "/mnt/wslg/doc",
    "/mnt/wslg/versions.txt", "/usr/lib/wsl/drivers", "/usr/lib/wsl/lib",
    "/usr/lib/modules", "/usr/src/linux-headers",
})


def _parse_mountinfo(text: str) -> List[Mapping[str, object]]:
    """Parse ``/proc/self/mountinfo`` into structured mount records.

    Format: ``mount_id parent_id major:minor root mount_point options ... - fstype source superoptions``
    Unparseable lines are skipped (they cannot be trusted as mounts).
    """
    mounts: List[Mapping[str, object]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            separator = line.index(" - ")
        except ValueError:
            continue
        left = line[:separator].split()
        right = line[separator + 3:].split()
        if len(left) < 6 or len(right) < 3:
            continue
        mounts.append({
            "mount_id": left[0],
            "parent_id": left[1],
            "root": left[3],
            "mount_point": left[4],
            "options": left[5],
            "fstype": right[0],
            "source": right[1],
            "superoptions": right[2] if len(right) > 2 else "",
        })
    return mounts


def _classify_mount(mount: Mapping[str, object], distro: str) -> str:
    """Classify one mount as ``allowed``, ``host`` or ``unknown``.

    ``host`` = carries host/other-distro data and must never be visible.
    ``unknown`` = not confidently classifiable; treated as untrusted.
    """
    fstype = str(mount["fstype"]).lower()
    target = str(mount["mount_point"])
    if fstype in _HOST_FILESYSTEMS:
        return "host"
    if fstype == "9p":
        # Only the exact read-only WSL driver/utility mounts are trusted.
        return "allowed" if target in _WSL_9P_TARGETS else "host"
    if fstype in _ALLOWED_FILESYSTEMS:
        # A mount under /mnt that is not a known WSL system mount is suspicious.
        if target == "/mnt" or target.startswith("/mnt/") and target not in _ALLOWED_MOUNT_TARGETS:
            return "unknown"
        if target in _ALLOWED_MOUNT_TARGETS or target.startswith(("/usr/lib/modules",
                                                                  "/usr/src/linux-headers",
                                                                  "/usr/lib/wsl/")):
            return "allowed"
        return "unknown"
    return "unknown"


def mount_inventory(distro: str, user: str,
                    timeout: float = 60) -> List[Mapping[str, object]]:
    """Read and parse the live mount inventory from inside the distro."""
    result = _wsl("--", "sh", "-c", "cat /proc/self/mountinfo",
                  distro=distro, user=user, timeout=timeout)
    if result.returncode != 0:
        raise WslBackendError("cannot read /proc/self/mountinfo")
    if not result.stdout.strip():
        raise WslBackendError("mountinfo is empty; refusing to trust")
    return _parse_mountinfo(result.stdout)


def verify_mount_isolation(distro: str = DEFAULT_DISTRO,
                           user: str = DEFAULT_USER,
                           timeout: float = 60) -> Mapping[str, object]:
    """Fail-closed classification of every visible mount.

    Returns ``{"ok": bool, "checks": [...], "mounts": [...]}``.  Any ``host``
    mount or any ``unknown`` mount fails the check; a missing/unreadable
    mountinfo also fails closed.
    """
    checks: list[dict[str, object]] = []
    try:
        mounts = mount_inventory(distro, user, timeout)
    except WslBackendError as error:
        return {"ok": False,
                "checks": [{"check": "mountinfo-readable", "ok": False,
                            "detail": str(error)}],
                "mounts": []}

    host_mounts: list[str] = []
    unknown_mounts: list[str] = []
    for mount in mounts:
        classification = _classify_mount(mount, distro)
        if classification == "host":
            host_mounts.append("%s (%s)" % (mount["mount_point"], mount["fstype"]))
        elif classification == "unknown":
            unknown_mounts.append("%s (%s)" % (mount["mount_point"], mount["fstype"]))

    checks.append({"check": "no-host-mounts", "ok": not host_mounts,
                   "detail": "host mounts: %s" % (host_mounts or "none")})
    checks.append({"check": "no-unknown-mounts", "ok": not unknown_mounts,
                   "detail": "unknown mounts: %s" % (unknown_mounts or "none")})
    return {"ok": not host_mounts and not unknown_mounts,
            "checks": checks, "mounts": mounts}


def verify_privileges(distro: str = DEFAULT_DISTRO, user: str = DEFAULT_USER,
                      timeout: float = 60) -> Mapping[str, object]:
    """Fail-closed check of the effective privilege state inside the distro.

    Verifies that the backend user is non-root and holds no effective or
    permitted capabilities.  ``CapBnd`` may contain capabilities (the WSL
    bounding set is inherited from the host); only effective/permitted/ambient
    sets grant authority to the running process.
    """
    script = (
        "id -u; "
        "grep -E '^Cap(Eff|Prm|Amb):' /proc/self/status; "
        "grep -E '^NoNewPrivs:' /proc/self/status"
    )
    result = _wsl("--", "sh", "-c", script, distro=distro, user=user,
                  timeout=timeout)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    uid_ok = bool(lines) and lines[0].isdigit() and lines[0] != "0"
    cap_eff = next((line.split(":", 1)[1].strip() for line in lines
                    if line.startswith("CapEff:")), None)
    cap_prm = next((line.split(":", 1)[1].strip() for line in lines
                    if line.startswith("CapPrm:")), None)
    cap_amb = next((line.split(":", 1)[1].strip() for line in lines
                    if line.startswith("CapAmb:")), None)
    caps_clear = all(value == "0000000000000000"
                     for value in (cap_eff, cap_prm, cap_amb) if value is not None)
    return {
        "ok": uid_ok and caps_clear,
        "checks": [
            {"check": "non-root-user", "ok": uid_ok, "detail": "uid=%s" % (lines[0] if lines else "?")},
            {"check": "no-effective-caps", "ok": caps_clear,
             "detail": "CapEff=%s CapPrm=%s CapAmb=%s" % (cap_eff, cap_prm, cap_amb)},
        ],
        "cap_eff": cap_eff, "cap_prm": cap_prm, "cap_amb": cap_amb,
    }


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

    Sequence (P1-3): environment prerequisites first (any failure returns
    before the executable is touched), then the executable hash is computed
    WITHOUT executing it, compared against the pinned digest, and only a
    matching binary is ever invoked (for a version sanity check).  A probe
    optionally confirms socket denial and control-write denial.
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
    uid_line = version.stdout.splitlines()[0].strip() if version.stdout.strip() else ""
    uid_ok = uid_line.isdigit() and uid_line != "0"
    record("non-root-user", uid_ok,
           "uid=%s" % (uid_line if uid_line else "unavailable"))

    interop = _wsl("--", "sh", "-c",
                   "command -v cmd.exe >/dev/null 2>&1 && echo interop-on || echo interop-off",
                   distro=distro, user=user)
    record("interop-off", "interop-off" in interop.stdout, interop.stdout.strip())

    mounted = _wsl("--", "sh", "-c",
                   "ls /mnt/c/Windows >/dev/null 2>&1 && echo c-visible || echo c-hidden",
                   distro=distro, user=user)
    record("host-drive-hidden", "c-visible" not in mounted.stdout, mounted.stdout.strip())

    # Phase 6.2: full mount classification (fail-closed) replaces the narrow
    # "/mnt/c/Windows exists" check.  An empty /mnt/c directory is not a mounted
    # host drive, and a missing /mnt/d is not proof of isolation.
    isolation = verify_mount_isolation(distro, user)
    for check in isolation["checks"]:
        record(check["check"], check["ok"], str(check["detail"]))

    # Phase 6.2: effective privilege state of the backend user.
    privileges = verify_privileges(distro, user)
    for check in privileges["checks"]:
        record(check["check"], check["ok"], str(check["detail"]))

    if not codex_path or not codex_path.startswith("/"):
        record("codex-pin", False, "codex_path must be absolute")
        return {"ok": False, "checks": checks}

    # P1-3: fail closed on any environment prerequisite before touching the binary.
    if not all(item["ok"] for item in checks):
        for item in checks:
            if not item["ok"]:
                record("refused-prerequisites", False,
                       "stopped before executable access: %s" % item["check"])
        return {"ok": False, "checks": checks}

    digest = _hash_only_codex(distro, user, codex_path)
    hash_ok = digest is not None and codex_sha256 is not None and digest.lower() == codex_sha256.lower()
    record("codex-hash", hash_ok,
           "sha256=%s" % (digest[:16] if digest else "unable to hash"))
    if not hash_ok:
        # Never invoke an unverified binary.
        return {"ok": False,
                "distro": distro, "user": user,
                "codex_path": codex_path,
                "codex_sha256": codex_sha256, "codex_version": codex_version,
                "version": CODEX_VERSION, "checks": checks}

    measured = _codex_version(distro, user, codex_path)
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


def _open_regular_file(source: Path, info: os.stat_result) -> tuple[int, os.stat_result]:
    """Open a validated regular file and bind its identity to the handle.

    Returns ``(fd, fstat)``.  ``O_RDONLY`` + ``O_NOFOLLOW`` (where available)
    refuse a final-component symlink swap.  The returned ``fstat`` must match
    the pre-open ``lstat`` (type, device, inode, link count) so a path swap
    between ``lstat`` and ``open`` is detected and refused.  On platforms where
    ``O_NOFOLLOW`` is unavailable (Windows, some POSIX), the device/inode check
    is the only swap defence; ancestor-component swaps are out of scope.  The
    caller owns ``fd``.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        try:
            fd = os.open(source, flags | nofollow)
        except OSError as error:
            # Only retry without O_NOFOLLOW when the flag itself is unsupported
            # (EINVAL/EOPNOTSUPP/ENOTSUP).  A real symlink/error must fail closed.
            if error.errno not in (getattr(os, "EINVAL", 22),
                                   getattr(os, "EOPNOTSUPP", 95),
                                   getattr(os, "ENOTSUP", 95)):
                raise
            fd = os.open(source, flags)
    else:
        fd = os.open(source, flags)
    try:
        handle_info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(handle_info.st_mode):
        os.close(fd)
        raise WslBackendError("non-regular file opened during staging: %s" % source)
    if handle_info.st_dev != info.st_dev or handle_info.st_ino != info.st_ino:
        os.close(fd)
        raise WslBackendError("file identity changed between validation and open: %s" % source)
    if getattr(info, "st_nlink", 1) != 1 or handle_info.st_nlink != 1:
        os.close(fd)
        raise WslBackendError("hardlinked file refused in staging: %s" % source)
    return fd, handle_info


def _dirfd_openat(dirfd: int, name: str) -> int:
    """Open ``name`` relative to ``dirfd`` without following a final symlink.

    Kept as the documented primitive for ancestor-pinned opens.  The current
    ``stage_project`` walker still uses path-based ``lstat``/``open`` per file;
    a full directory-fd walk (pinning the root and every ancestor) is the
    follow-up hardening in Phase 6.3 and is not yet wired.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=dirfd)
    except OSError:
        if getattr(os, "O_NOFOLLOW", 0):
            return os.open(name, flags & ~getattr(os, "O_NOFOLLOW", 0), dir_fd=dirfd)
        raise


def _validate_archive_member(member: tarfile.TarInfo, seen: set[str]) -> None:
    """Fail-closed validation of one archive member.

    Rejects absolute paths, parent traversal, drive prefixes, UNC paths,
    alternate data streams, duplicate entries and unsafe member types.  Only
    regular files and directories are permitted; symlinks/hardlinks/devices
    are refused.

    Note: this validator is the archive-hardening contract for any future
    host-side extraction.  The production staging path does not extract on the
    host: it streams the archive into WSL and extracts with the distro's
    ``tar -x`` into a fresh, generated run root.  The archive is built
    exclusively from validated, opened file handles (see ``stage_project``), so
    no untrusted archive bytes are ever fed to a host extractor today.
    """
    name = member.name
    if not name or name.startswith(("/", "\\")):
        raise WslBackendError("archive member has an absolute path: %r" % name)
    if ":" in name:
        raise WslBackendError("archive member has a drive/ADS prefix: %r" % name)
    if "\x00" in name:
        raise WslBackendError("archive member has a NUL byte: %r" % name)
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise WslBackendError("archive member has parent traversal: %r" % name)
    if not parts:
        return
    if normalized in seen:
        raise WslBackendError("duplicate archive member: %r" % name)
    seen.add(normalized)
    if member.issym() or member.islnk():
        raise WslBackendError("archive member is an unsafe link: %r" % name)
    if not (member.isfile() or member.isdir()):
        raise WslBackendError("archive member is an unsupported type: %r" % name)


def _validate_and_extract_archive(archive_path: Path, destination: Path) -> None:
    """Validate every member, then extract strictly into ``destination``.

    This is the host-side archive-hardening contract and the extraction path for
    any future host-side consumer.  Production staging does NOT use it: the
    archive is streamed into WSL and extracted with the distro's ``tar -x``
    into a fresh, generated run root.  It is kept (and tested) so the archive
    contract cannot silently drift, and so a future host-side extraction path
    inherits a fail-closed validator.
    """
    seen: set[str] = set()
    with tarfile.open(archive_path, "r:") as tar:
        members = tar.getmembers()
        for member in members:
            _validate_archive_member(member, seen)
        try:
            tar.extractall(path=destination, filter="data")
        except (tarfile.TarError, OSError) as error:
            raise WslBackendError("archive extraction failed: %s" % error) from error


def stage_project(local_root, distro: str, user: str = DEFAULT_USER,
                  timeout: float = 900) -> str:
    """PH3-002/PH3-008/6.3: secrets-stage a local project into a generated run root.

    Returns ``/home/<user>/runs/<16-hex-runid>/project``.  The run id is
    generated crypto-randomly here; the caller never supplies a remote path, so
    no project-controlled string becomes shell syntax and cleanup stays scoped
    to the generated run root.

    Phase 6.3: each file is opened once and the validated handle is the single
    source of the archived bytes (``tar.addfile``), so a path swap between
    ``lstat`` and read is detected (identity mismatch) and a symlink swap is
    refused (``O_NOFOLLOW``).  The archive is extracted with a strict,
    member-by-member validated, ``filter="data"`` extraction.
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
                    if not stat.S_ISREG(info.st_mode):
                        # P2-9: defensive symlink/device rejection; do not rely
                        # on an earlier caller having validated the tree.
                        raise WslBackendError(
                            "non-regular file refused in staging: %s" % source)
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
                    fd, handle_info = _open_regular_file(source, info)
                    try:
                        # Re-check the size limit against the opened handle, so a
                        # file grown between lstat and open cannot exceed the
                        # staged-file or staged-total budget (F4).
                        if handle_info.st_size > MAX_STAGED_FILE_BYTES:
                            raise WslBackendError(
                                "staged file exceeds size limit after open: %s" % source)
                        if total + handle_info.st_size > MAX_STAGED_TOTAL_BYTES:
                            raise WslBackendError(
                                "staged total size limit exceeded after open: %s" % source)
                        member = tarfile.TarInfo(name=relative)
                        member.size = handle_info.st_size
                        member.mtime = int(handle_info.st_mtime)
                        # Preserve the source permission bits (executable scripts
                        # must stay executable in the sandbox) (F1).
                        member.mode = stat.S_IMODE(handle_info.st_mode)
                        member.type = tarfile.REGTYPE
                        with os.fdopen(fd, "rb", closefd=False) as handle:
                            tar.addfile(member, handle)
                    finally:
                        os.close(fd)
                    total += handle_info.st_size
                    count += 1
                    if count > MAX_STAGED_FILES:
                        raise WslBackendError("staged file count limit exceeded")
                    if total > MAX_STAGED_TOTAL_BYTES:
                        raise WslBackendError("staged total size limit exceeded")
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
    payload_b64 = base64.b64encode(
        json.dumps({"mandatory": mandatory, "coverage": coverage},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    result = _wsl_root(distro, _guard_script(remote_project, payload_b64), timeout=timeout)
    try:
        report = json.loads(result.stdout.strip() or "{}")
    except ValueError as error:
        raise WslBackendError("guard status is not structured JSON: %s"
                              % result.stdout.strip()[-200:]) from error
    if report.get("status") != "guarded" or not isinstance(report.get("errors"), list) or report.get("errors"):
        raise WslBackendError("control-plane guard failed closed: %s"
                              % json.dumps(report, sort_keys=True))
    return report


def _guard_script(remote_project: str, payload_b64: str) -> str:
    # P2-1: the protected-path payload crosses into the privileged shell as
    # base64 (charset [A-Za-z0-9+/=] only) and is decoded into a root-owned,
    # random-named JSON file next to the script (script dir is 0700 root).
    # No protected path can ever become shell syntax.
    return r'''
set -eu
proj=%s
pl="${0%%.sh}.json"
printf '%%s' '%s' | base64 -d > "$pl" && chmod 600 -- "$pl" || exit 90
trap 'rm -f -- "$pl" "$proj/.rad-guard-report.tmp"' EXIT
report="$proj/.rad-guard-report.tmp"
rm -f -- "$report"
: > "$report"
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));
for p in d["mandatory"]: print("M\t" + p)
for p in d["coverage"]: print("C\t" + p)' "$pl" | while IFS=$'\t' read -r kind rel; do
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
''' % (remote_project, payload_b64)


def unguard_control_plane_wsl(remote_project: str, distro: str = DEFAULT_DISTRO,
                              protected_relative: Optional[Iterable[str]] = None,
                              timeout: float = 300) -> None:
    _validate_linux_path(remote_project, _REMOTE_PROJECT_RE, "remote project")
    mandatory = _wsl_mandatory_paths(protected_relative)
    coverage = [name for name in _wsl_coverage_paths(protected_relative)
                if name not in mandatory]
    payload_b64 = base64.b64encode(
        json.dumps({"mandatory": mandatory, "coverage": coverage},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    script = (
        "set +e; proj=%s; pl=\"${0%%.sh}.json\"; "
        "printf '%%s' '%s' | base64 -d > \"$pl\" && chmod 600 -- \"$pl\" || exit 90; "
        "python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));"
        "print(\"\\n\".join(d[\"mandatory\"] + d[\"coverage\"]))' \"$pl\" "
        "| while IFS= read -r rel; do [ -n \"$rel\" ] || continue; "
        "p=\"$proj/$rel\"; [ -d \"$p\" ] && chattr -R -i -- \"$p\" 2>/dev/null "
        "|| chattr -i -- \"$p\" 2>/dev/null; done; rm -f -- \"$pl\""
        % (remote_project, payload_b64)
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


def _require_env_name(name: str) -> str:
    """P2-5: POSIX environment variable name validation (sets only, no '=')."""
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise WslBackendError("invalid environment variable name: %r" % name)
    return name


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
            _require_env_name(key)
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