"""Fail-closed bootstrap. No target executable is used to establish trust.

There deliberately is no generic 'trust this backend' flag. A backend must gain
an implementation and native coverage in a reviewed RAD release before launch.
Legacy launch is a separate, explicitly acknowledged, non-secure operation.
"""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from .baseline import load_verified_installation, verify_target
from .guard import lock_control_plane
from .policy import canonicalize_existing_directory, ensure_disjoint_paths


class SecurityBoundaryError(RuntimeError):
    pass


class SecureModeUnavailable(SecurityBoundaryError):
    pass


class NetworkPolicy(str, Enum):
    NONE = "NO NETWORK"
    LOOPBACK = "LOOPBACK-ONLY"
    DESTINATIONS = "EXPLICITLY APPROVED DESTINATIONS"
    TRUSTED = "UNRESTRICTED TRUSTED MODE"


@dataclass(frozen=True)
class Capability:
    runtime: str
    status: str
    version_tested: str
    filesystem: str
    network: str
    project_extensions: str
    credentials: str
    processes: str
    control_plane: str
    native_test: str


def capability_matrix():
    """Release-owned facts, never supplied by a project or writable report."""
    return [
        Capability("codex-wsl", "SUPPORTED", "0.153.4 (linux, WSL2 RAD-Secure-Test)",
                   "verified natively; Linux bwrap sandbox, project workspace write, control plane immutable",
                   "network disabled at socket layer; private netns; DNS blocked",
                   "sandboxed process tree; no project extension startup outside sandbox",
                   "constructed allowlist environment; no inherited secrets",
                   "bwrap process isolation (uid 1000); base image stays clean",
                   "immutable control plane (root-owned chattr +i); baseline verified before mirror",
                   "native probes: socket/interop/control-write denial PASS"),
        Capability("codex", "PARTIALLY VERIFIED", "0.154.0",
                   "native sandbox probe; full agent integration unverified",
                   "full agent integration unverified",
                   "full startup isolation unverified",
                   "launcher allowlist implemented; agent integration unverified",
                   "full agent integration unverified",
                   "installed baseline verifier; runtime write boundary unverified",
                   "native Windows sandbox CLI only, not a Secure Mode certification"),
        *[Capability(name, "TRUSTED-PROJECT ONLY", "not natively verified",
                     "unverified", "unverified", "unverified", "unverified",
                     "unverified", "installed baseline verifier only", "no")
          for name in ("opencode", "claude", "cursor")],
    ]


def _capability(runtime):
    for row in capability_matrix():
        if row.runtime == runtime:
            return row
    raise SecureModeUnavailable("Unknown runtime: Secure Mode is UNSUPPORTED")


def _is_reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def inspect_project(project, max_entries=50000, max_depth=64):
    """Inventory names only; no importing, shelling out, config expansion or copy.

    Reparse points, symlinks, hardlinks and special files fail closed. This is a
    preflight, NOT a substitute for an OS sandbox against concurrent mutation.
    Since no certified runtime is currently enabled, no executable can follow it.
    """
    project = canonicalize_existing_directory(Path(project))
    stack = [(project, 0)]
    count = 0
    executable_configuration = []
    discovery_dirs = {".opencode", ".codex", ".claude", ".cursor", ".agents",
                      ".vscode", ".idea", ".devcontainer"}
    discovery_files = {"opencode.json", "opencode.jsonc", ".mcp.json",
                       "package.json", "pyproject.toml", "AGENTS.md", "CLAUDE.md"}
    while stack:
        directory, depth = stack.pop()
        if depth > max_depth:
            raise SecurityBoundaryError("Project traversal depth limit exceeded")
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                if count > max_entries:
                    raise SecurityBoundaryError("Project entry limit exceeded")
                # Windows DirEntry.stat may report st_nlink=0; obtain a full
                # lstat rather than treating the directory cache as identity.
                info = os.lstat(entry.path)
                rel = Path(entry.path).relative_to(project).as_posix()
                if entry.is_symlink() or _is_reparse(info):
                    raise SecurityBoundaryError("Linked/reparse project entry refused: " + rel)
                if stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        raise SecurityBoundaryError("Hardlinked project entry refused: " + rel)
                elif not stat.S_ISDIR(info.st_mode):
                    raise SecurityBoundaryError("Special project entry refused: " + rel)
                if entry.name in discovery_dirs or entry.name in discovery_files:
                    executable_configuration.append(rel)
                if stat.S_ISDIR(info.st_mode) and entry.name != ".git":
                    stack.append((Path(entry.path), depth + 1))
    return {"entries": count, "executable_configuration": sorted(executable_configuration)}


def _verified_installation(installation, project, expected_release_sha256):
    installation = canonicalize_existing_directory(Path(installation))
    project = canonicalize_existing_directory(Path(project))
    ensure_disjoint_paths(installation, project)
    manifest = load_verified_installation(installation, expected_release_sha256)
    return installation, project, manifest


def verify_project(installation, project, expected_release_sha256):
    installation, project, manifest = _verified_installation(
        installation, project, expected_release_sha256)
    inventory = inspect_project(project)
    verification = verify_target(project, manifest)
    if not verification.ok:
        raise SecurityBoundaryError("Target baseline mismatch: " + "; ".join(verification.issues))
    return inventory


def prepare_secure_launch(installation, project, runtime,
                          expected_release_sha256, network=NetworkPolicy.NONE.value,
                          codex_sha256=None, codex_path=None, codex_version=None):
    """No runtime version probe, extension load or process start before admission."""
    installation, project, manifest = _verified_installation(
        installation, project, expected_release_sha256)
    inspect_project(project)
    try:
        selected_network = NetworkPolicy(network)
    except ValueError as exc:
        raise SecurityBoundaryError("Unknown network policy") from exc
    if selected_network is NetworkPolicy.TRUSTED:
        raise SecurityBoundaryError("Unrestricted network is not a Secure Mode policy")
    capability = _capability(runtime)
    if capability.status != "SUPPORTED":
        raise SecureModeUnavailable(
            f"{runtime}: {capability.status}; Secure Mode refused BEFORE runtime startup. "
            "No project plugin, script or checker has been executed.")
    # A status string alone must never activate an unimplemented backend.
    verification = verify_target(project, manifest)
    if not verification.ok:
        raise SecurityBoundaryError("Target baseline mismatch: " + "; ".join(verification.issues))
    if runtime == "codex-wsl":
        from .wsl_backend import (DEFAULT_DISTRO, DEFAULT_USER,
                                  CODEX_VERSION, verify_wsl_backend)
        if not codex_sha256:
            raise SecureModeUnavailable(
                "codex-wsl Secure Mode requires the independently pinned Codex SHA-256; "
                "Secure Launch refuses startup without it.")
        backend = verify_wsl_backend(
            distro=DEFAULT_DISTRO, user=DEFAULT_USER,
            codex_path=codex_path or "/usr/local/bin/codex",
            codex_sha256=codex_sha256,
            codex_version=codex_version or CODEX_VERSION,
            probe=True)
        if not backend["ok"]:
            failures = [c["detail"] for c in backend["checks"] if not c["ok"]]
            raise SecureModeUnavailable(
                "codex-wsl backend verification failed: " + "; ".join(failures))
        return dict(backend, runtime=runtime)
    raise SecureModeUnavailable("No certified secure execution backend in this release")


def isolated_environment(executable, state_directory, parent=None):
    """Construct, do not filter, an execution environment. Never read .env files.

    Even trusted-project mode does not inherit provider credentials or Git/SSH/
    package-manager/Python/Node configuration variables. Runtime authentication
    discovered on disk is a separate risk in explicitly NON-SECURE legacy mode.
    """
    parent = os.environ if parent is None else parent
    env = {}
    # No PATH inherited from the user; no current-directory entry in generated PATH.
    executable = Path(executable)
    state_directory = Path(state_directory)
    if not executable.is_absolute() or not state_directory.is_absolute():
        raise SecurityBoundaryError("Environment roots must be absolute")
    if os.name == "nt":
        # Do not accept an attacker-supplied SystemRoot or COMSPEC.
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if not 0 < length < len(buffer):
            raise SecurityBoundaryError("Cannot determine trusted Windows directory")
        windows = Path(buffer.value)
        env.update(SystemRoot=str(windows), WINDIR=str(windows),
                   COMSPEC=str(windows / "System32" / "cmd.exe"),
                   PATH=os.pathsep.join((str(executable.parent), str(windows / "System32"))))
    else:
        env["PATH"] = os.pathsep.join((str(executable.parent), "/usr/bin", "/bin"))
    env.update(TEMP=str(state_directory), TMP=str(state_directory),
               TMPDIR=str(state_directory), LANG="C.UTF-8")
    return env


def verify_runtime_executable(executable, project, expected_sha256):
    path = Path(executable)
    if not path.is_absolute():
        raise SecurityBoundaryError("Runtime executable must be an absolute pinned path")
    canonicalize_existing_directory(path.parent)
    ensure_disjoint_paths(path.parent, Path(project))
    info = path.lstat()
    if path.is_symlink() or _is_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SecurityBoundaryError("Runtime executable must be a non-linked regular file")
    if info.st_size > 512 * 1024 * 1024:
        raise SecurityBoundaryError("Runtime executable exceeds size limit")
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise SecurityBoundaryError("A full lowercase SHA-256 runtime pin is required")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _file_hash(source)
    if digest != expected_sha256:
        raise SecurityBoundaryError("Runtime executable differs from the maintainer pin")
    return path


def _file_hash(source):
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def launch_trusted_project(installation, project, runtime, expected_release_sha256,
                           executable, executable_sha256, acknowledge=False,
                           guard_control_plane=False):
    """Explicit compatibility path. Never called as a Secure Mode fallback.

    With ``guard_control_plane`` the repository control plane is locked at the
    OS boundary (deny write/delete/create for every process, including all
    descendants of the launched runtime) before the executable starts, verified,
    and restored exactly when the session ends.
    """
    if acknowledge is not True:
        raise SecurityBoundaryError("Explicit --acknowledge-trusted-project is required")
    installation, project, _ = _verified_installation(
        installation, project, expected_release_sha256)
    _capability(runtime)
    executor = verify_runtime_executable(executable, project, executable_sha256)
    # No arbitrary runtime arguments, environment files or executable resolution.
    import tempfile

    if guard_control_plane:
        import tempfile
        guard = lock_control_plane(project)
        try:
            guard.verify()
            with tempfile.TemporaryDirectory(prefix="rad-guarded-run-") as state:
                env = isolated_environment(executor, Path(state))
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                return subprocess.call([str(executor)], cwd=str(project), env=env,
                                       shell=False, creationflags=flags)
        finally:
            guard.restore()
    import tempfile
    with tempfile.TemporaryDirectory(prefix="rad-trusted-run-") as state:
        env = isolated_environment(executor, Path(state))
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        return subprocess.call([str(executor)], cwd=str(project), env=env,
                               shell=False, creationflags=flags)


def matrix_as_dicts():
    return [asdict(row) for row in capability_matrix()]
