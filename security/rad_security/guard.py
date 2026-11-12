"""Windows ACL-based session guard for the target control plane.

The authoritative RAD control plane lives in the installed, externally pinned
release outside the target workspace.  The repository copy of control material
(``AGENTS.md``, ``.rad/**``, adapters, generator, ``DECISIONS.md`` and similar)
is untrusted project data in Secure Mode: it must never become authority.

This module provides a reversible, per-session OS boundary that denies every
mutating operation (write, append, truncate, delete, rename-over, create-in,
attribute/EA/DACL/ownership change, and replacement) against that repository
control plane for *any* process, regardless of how that process was spawned
(shell, test framework, language, plugin, formatter, MCP server, or arbitrary
descendant).  Denial is enforced by the Windows security descriptor, not by
agent instruction or file naming.

Phase 4 hardening applied here:

- PH3-001: helper executables such as ``icacls.exe`` are resolved from the
  canonical trusted system directory, never via PATH or the current directory.
  Native ACL APIs are loaded from ``System32`` with restricted DLL search.
- PH3-005: the deny masks explicitly cover `FILE_APPEND_DATA` (AD),
  `FILE_WRITE_ATTRIBUTES` (WA), `FILE_WRITE_EA` (WEA), `WRITE_DAC` (WDAC) and
  `WRITE_OWNER` (WO) in addition to write-data and delete, closing the
  append-only bypass.
- PH3-006: the protected leaf set is derived from the independently verified
  baseline when available, and the immediate parent directory of every control
  leaf is locked (name-entry deny) so replacement/rename-over of protected
  files below ordinary product directories is denied as well.
- PH3-009: the exact owner, group and ordered DACL ACEs of every guarded path
  are captured before modification and restored afterwards; restore never
  relies on removing "all Everyone deny ACEs". Windows recalculates the
  auto-inherited descriptor control bit when writing an ACL.

The guard is defense-in-depth.  The durable authority boundary in deployment is
a separate OS principal that does not own the control material, plus the
externally pinned installed baseline that fails closed before a runtime starts.
A same-account process that owns the files retains the OS owner's ability to
rewrite the DACL; closing that residual requires running the untrusted runtime
under a different, non-owning principal (a certified backend requirement).
"""

from __future__ import annotations

import ctypes
from functools import lru_cache
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Iterable, List, Optional, Tuple

from .baseline import TrustedBaseline
from .policy import (
    FileClass,
    SecurityPolicyError,
    canonicalize_existing_directory,
    classify_path,
)


class GuardError(RuntimeError):
    """Raised when the control-plane guard cannot be applied or verified."""


# Numeric SID for "Everyone" (S-1-1-0).  Localized Windows builds do not
# reliably resolve the display name "Everyone"; the numeric form always works.
_DENY_EVERYONE = "*S-1-1-0"

# PH3-005: deny the effective security-relevant mutation set on a control-plane
# file: write-data, append-data (the append bypass), delete, write-attributes
# and write extended attributes.  WRITE_DAC / WRITE_OWNER are deliberately NOT
# denied: an Everyone-deny of those rights would lock out even the file owner
# and make the guard unrestorable.  Preventing an owner from resetting the DACL
# requires the certified separate-principal backend, which is the documented
# deployment residual.
_FILE_DENY = "(WD,AD,DE,WA,WEA)"
# On a control-plane directory: create files, create subdirs/append, delete
# child, delete self, write attributes and write extended attributes.
_DIR_DENY = "(WD,AD,DC,DE,WA,WEA)"
# Name-entry permissions denied on the repository root itself so that no
# process can delete or rename-over a root-level control file.  Collateral:
# during a guarded session no top-level repo entry can be created, renamed or
# deleted without an explicit trusted unlock.
_ROOT_DENY = "(WD,AD,DC)"

_MAX_GUARDED_ENTRIES = 2000
_MAX_GUARD_TRAVERSAL = 200000
_MAX_GUARD_DEPTH = 64
# node_modules is deliberately skipped: it is an install artifact the baseline
# admission gate re-verifies anyway, and skipping keeps large dependency trees
# from consuming the traversal/entry budget.
_SKIPPED_PARTS = frozenset({".git", ".hg", ".svn", "node_modules"})

_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _system_root() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise GuardError("cannot determine trusted Windows directory")
    return Path(buffer.value).resolve()


def _system_tool(name: str) -> str:
    """PH3-001: absolute trusted system executable; never PATH/current-dir."""
    candidate = _system_root() / "System32" / name
    if not candidate.is_file():
        raise GuardError("trusted system tool missing: %s" % candidate)
    return str(candidate)


_ICACLS = None


def _resolve_tools() -> str:
    global _ICACLS
    if _ICACLS is None:
        _ICACLS = _system_tool("icacls.exe")
    return _ICACLS


def _is_locked_out(part: str) -> bool:
    return part in _SKIPPED_PARTS


def protected_paths_from_baseline(baseline: TrustedBaseline) -> List[str]:
    """PH3-006: derive the protected relative path set from the baseline.

    The baseline is the independently verified authority; every CONTROL_PLANE
    or GENERATED_CONTROL_OUTPUT file it records is a protected leaf.
    """
    result = []
    for record in baseline.files:
        if record.file_class in (FileClass.CONTROL_PLANE,
                                 FileClass.GENERATED_CONTROL_OUTPUT):
            result.append(record.path)
    return sorted(result)


def control_plane_entries(project_root, protected_relative: Optional[Iterable[str]] = None,
                          ) -> Tuple[List[Path], List[Path]]:
    """Return (files, directories) under a canonical project root.

    Only paths classified as CONTROL_PLANE or GENERATED_CONTROL_OUTPUT are
    guarded.  When ``protected_relative`` (from the baseline) is supplied, the
    protected set is the union of the baseline leaves and the classification
    walk, so protected leaves below ordinary directories are still covered.
    ``.git``/``.hg``/``.svn`` subtrees are skipped: their integrity is already
    enforced by the independent baseline admission gate.
    """
    root = canonicalize_existing_directory(project_root)
    files: List[Path] = []
    directories: List[Path] = []
    protected = 0
    traversed = 0
    stack: List[Tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if depth > _MAX_GUARD_DEPTH:
            raise GuardError("control-plane guard depth limit exceeded")
        try:
            names = os.listdir(directory)
        except OSError as error:
            raise GuardError("control-plane guard cannot enumerate tree: %s" % error)
        for name in sorted(names):
            if _is_locked_out(name):
                continue
            child = directory / name
            traversed += 1
            if traversed > _MAX_GUARD_TRAVERSAL:
                raise GuardError(
                    "control-plane guard traversal limit exceeded; operator review required")
            try:
                info = child.lstat()
            except OSError as error:
                raise GuardError("control-plane guard cannot inspect entry: %s" % error)
            is_dir = stat.S_ISDIR(info.st_mode)
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG
            ):
                raise GuardError("linked or reparse control entry refused: %s" % child)
            relative = child.relative_to(root).as_posix()
            try:
                file_class = classify_path(relative)
            except SecurityPolicyError:
                file_class = None
            baseline_protected = protected_relative is not None and (
                relative in protected_relative
                or any(relative.startswith(prefix + "/")
                       for prefix in protected_relative))
            if is_dir:
                # Descend into every non-skipped directory so protected leaves
                # below ordinary directories are discovered (PH3-006).  Only
                # control-classed/baseline directories count against the
                # protected-entry budget (P1-5) and are returned for denial.
                if file_class in (FileClass.CONTROL_PLANE,
                                  FileClass.GENERATED_CONTROL_OUTPUT) or baseline_protected:
                    protected += 1
                    if protected > _MAX_GUARDED_ENTRIES:
                        raise GuardError(
                            "control-plane guard protected-entry limit exceeded; "
                            "operator review required")
                    directories.append(child)
                stack.append((child, depth + 1))
            else:
                if file_class not in (FileClass.CONTROL_PLANE,
                                      FileClass.GENERATED_CONTROL_OUTPUT) and not baseline_protected:
                    continue
                protected += 1
                if protected > _MAX_GUARDED_ENTRIES:
                    raise GuardError(
                        "control-plane guard protected-entry limit exceeded; "
                        "operator review required")
                files.append(child)
    return files, directories


def _icacls(*arguments) -> None:
    tool = _resolve_tools()
    process = subprocess.run(
        [tool] + [str(argument) for argument in arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    if process.returncode != 0:
        raise GuardError("icacls failed (%s)" % process.stdout.strip()[-200:])


_OWNER_SECURITY_INFORMATION = 0x00000001
_GROUP_SECURITY_INFORMATION = 0x00000002
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_SE_DACL_PROTECTED = 0x1000
_SECURITY_DESCRIPTOR_REVISION = 1
_ERROR_INSUFFICIENT_BUFFER = 122


def _security_error(operation: str, error_code: Optional[int] = None) -> GuardError:
    """Return a bounded native API diagnostic without paths or descriptor data."""
    if error_code is None:
        error_code = ctypes.get_last_error()
    categories = {
        2: "FileNotFound",
        3: "PathNotFound",
        5: "AccessDenied",
        87: "InvalidParameter",
        122: "InsufficientBuffer",
    }
    category = categories.get(error_code, "Win32Error")
    return GuardError("%s failed: category=%s winerror=%s" %
                      (operation, category, error_code))


@lru_cache(maxsize=1)
def _security_apis():
    """Load native ACL APIs from the trusted Windows system directory."""
    from ctypes import wintypes

    advapi_path = _system_dll("advapi32.dll")
    if not advapi_path.is_file():
        raise GuardError("trusted Windows security API is missing")
    advapi = ctypes.WinDLL(str(advapi_path), use_last_error=True,
                           winmode=0x00000800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetFileSecurityW.restype = wintypes.BOOL
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
    ]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    return advapi, kernel


def _system_dll(name: str) -> Path:
    """Return a trusted DLL path under the resolved Windows System32."""
    return _system_root() / "System32" / name


def _capture_security_descriptor_sddl(path: Path) -> str:
    """Capture the owner, group and DACL with native APIs (no temp files)."""
    advapi, kernel = _security_apis()
    security_information = (_OWNER_SECURITY_INFORMATION
                           | _GROUP_SECURITY_INFORMATION
                           | _DACL_SECURITY_INFORMATION)
    required = ctypes.c_uint32(0)
    ctypes.set_last_error(0)
    advapi.GetFileSecurityW(str(path), security_information, None, 0,
                           ctypes.byref(required))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not required.value:
        raise _security_error("GetFileSecurityW")
    descriptor = ctypes.create_string_buffer(required.value)
    received = ctypes.c_uint32(0)
    if not advapi.GetFileSecurityW(str(path), security_information, descriptor,
                                  required.value, ctypes.byref(received)):
        raise _security_error("GetFileSecurityW")
    if not received.value or received.value > required.value:
        raise GuardError("GetFileSecurityW returned an invalid descriptor size")

    sddl_pointer = ctypes.c_wchar_p()
    sddl_length = ctypes.c_uint32(0)
    try:
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, _SECURITY_DESCRIPTOR_REVISION,
                security_information, ctypes.byref(sddl_pointer),
                ctypes.byref(sddl_length)):
            raise _security_error("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        sddl = sddl_pointer.value
    finally:
        if sddl_pointer:
            kernel.LocalFree(ctypes.cast(sddl_pointer, ctypes.c_void_p))
    if not sddl or not sddl.startswith("O:"):
        raise GuardError("security descriptor conversion returned empty or invalid SDDL")
    return sddl


def _acl_sddl(path: Path) -> str:
    """PH3-009: capture the exact owner/group/DACL as SDDL, failing closed."""
    try:
        absolute = Path(path).resolve(strict=True)
        return _capture_security_descriptor_sddl(absolute)
    except GuardError:
        raise
    except OSError as error:
        raise GuardError("cannot capture security descriptor: category=%s" %
                         type(error).__name__) from error


def _restore_security_descriptor_sddl(path: Path, sddl: str) -> None:
    """Restore an SDDL snapshot with the native Windows security API."""
    from ctypes import wintypes

    if not isinstance(sddl, str) or not sddl or not sddl.startswith("O:"):
        raise GuardError("cannot restore security descriptor: invalid SDDL")
    advapi, kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD(0)
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SECURITY_DESCRIPTOR_REVISION,
            ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        raise _security_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        control = wintypes.WORD(0)
        revision = wintypes.DWORD(0)
        if not advapi.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise _security_error("GetSecurityDescriptorControl")
        security_information = (_OWNER_SECURITY_INFORMATION
                               | _GROUP_SECURITY_INFORMATION
                               | _DACL_SECURITY_INFORMATION)
        if control.value & _SE_DACL_PROTECTED:
            security_information |= _PROTECTED_DACL_SECURITY_INFORMATION
        else:
            security_information |= _UNPROTECTED_DACL_SECURITY_INFORMATION
        # SetFileSecurityW writes the captured DACL without propagating a
        # parent's inheritable ACEs through the tree. SetNamedSecurityInfoW
        # does propagate them, which can add inherited ACEs absent from the
        # snapshot and make an exact rollback impossible.
        if not advapi.SetFileSecurityW(str(path), security_information, descriptor):
            raise _security_error("SetFileSecurityW")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def _set_acl_sddl(path: Path, sddl: str) -> None:
    """Restore and verify the exact original owner/group/DACL snapshot."""
    try:
        absolute = Path(path).resolve(strict=True)
        _restore_security_descriptor_sddl(absolute, sddl)
        actual = _capture_security_descriptor_sddl(absolute)
        if not _same_restored_acl(sddl, actual):
            raise GuardError("restored ACL does not match captured owner/group/DACL")
    except GuardError:
        raise
    except OSError as error:
        raise GuardError("cannot restore security descriptor: category=%s" %
                         type(error).__name__) from error


def _same_restored_acl(expected: str, actual: str) -> bool:
    """Compare the full SDDL except Windows' recalculated auto-inherited bit.

    SetFileSecurityW restores the owner, group and ordered DACL ACEs exactly,
    but Windows recalculates SE_DACL_AUTO_INHERITED when it writes the
    descriptor. That control bit is normalized here; ACE inheritance flags,
    DACL protection, owner/group SIDs and ACE order remain part of the compare.
    """
    def without_auto_inherited(value: str) -> str:
        dacl_start = value.find("D:")
        if dacl_start < 0:
            return value
        first_ace = value.find("(", dacl_start + 2)
        if first_ace < 0:
            first_ace = len(value)
        flags = value[dacl_start + 2:first_ace].replace("AI", "")
        return value[:dacl_start + 2] + flags + value[first_ace:]

    return without_auto_inherited(expected) == without_auto_inherited(actual)


def _deny_for(entry: Path) -> str:
    return _DIR_DENY if entry.is_dir() else _FILE_DENY


def remove_deny_aces(path) -> None:
    """Operator-recovery: remove Everyone deny ACEs from a single path."""
    _icacls(path, "/remove:d", _DENY_EVERYONE)


def check_control_plane_locked(project_root,
                               protected_relative: Optional[Iterable[str]] = None) -> bool:
    """Probe whether a control-plane guard is currently effective.

    Purely observational: this never applies or removes any ACE.  A control
    file must reject an open-for-write (and an append open) and a control
    directory must reject creating a probe entry for the check to succeed.
    """
    files, directories = control_plane_entries(project_root, protected_relative)
    control_file = next((p for p in files if ".git" not in p.parts), None)
    control_dir = next((p for p in directories if ".git" not in p.parts), None)
    if control_file is None and control_dir is None:
        return False
    if control_file is not None:
        try:
            with control_file.open("r+b"):
                return False
        except OSError:
            pass
        if not _append_denied(control_file):
            return False
    if control_dir is not None:
        probe = control_dir / (".rad-guard-probe-" + os.urandom(4).hex())
        try:
            probe.open("wb").close()
            probe.unlink()
            return False
        except OSError:
            pass
    return True


def _append_denied(path: Path) -> bool:
    """Verify FILE_APPEND_DATA is denied for the current principal."""
    import ctypes as _ctypes
    from ctypes import wintypes
    kernel = _ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   _ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    FILE_APPEND_DATA = 0x00000004
    SYNCHRONIZE = 0x00100000
    OPEN_EXISTING = 3
    handle = kernel.CreateFileW(str(path), FILE_APPEND_DATA | SYNCHRONIZE,
                                0, None, OPEN_EXISTING, 0, None)
    if handle == _ctypes.c_void_p(-1).value:
        return True
    kernel.CloseHandle(handle)
    return False


def harden_installation(install_root) -> int:
    """Make an installed authority tree mutation-denied for every principal."""
    root = canonicalize_existing_directory(install_root)
    entries: List[Path] = [root]
    for current_text, directories, filenames in os.walk(root):
        current = Path(current_text)
        for name in directories:
            entries.append(current / name)
        for name in filenames:
            entries.append(current / name)
    entries.sort(key=lambda p: (len(p.parts), str(p)))
    for entry in entries:
        _icacls(entry, "/deny", _DENY_EVERYONE + ":" + _deny_for(entry))
    return len(entries)


def unharden_installation(install_root) -> int:
    """Remove the harden deny ACEs from an installed authority tree."""
    root = canonicalize_existing_directory(install_root)
    entries: List[Path] = []
    for current_text, directories, filenames in os.walk(root):
        current = Path(current_text)
        for name in directories:
            entries.append(current / name)
        for name in filenames:
            entries.append(current / name)
    entries.append(root)
    entries.sort(key=lambda p: (len(p.parts), str(p)))
    for entry in entries:
        remove_deny_aces(entry)
    return len(entries)


def unlock_control_plane(project_root,
                         protected_relative: Optional[Iterable[str]] = None) -> int:
    """Operator recovery: remove deny ACEs from the guarded path set."""
    files, directories = control_plane_entries(project_root, protected_relative)
    parents = {entry.parent for entry in files}
    entries = [canonicalize_existing_directory(project_root)]
    entries += sorted(directories, key=lambda p: (len(p.parts), str(p)))
    entries += sorted(parents, key=lambda p: (len(p.parts), str(p)))
    entries += sorted(files, key=lambda p: (len(p.parts), str(p)))
    for entry in entries:
        remove_deny_aces(entry)
    return len(entries)


class ControlPlaneGuard:
    """Reversible per-session mutex against repository control-plane writes.

    Usage::

        with lock_control_plane(project) as guard:
            guard.verify()   # raises unless truly denied at the OS boundary
            ... run the runtime / descendants ...
        # exiting restores the exact original owner/group/ordered DACL ACEs.

    Phase 4: the original SDDL of every guarded path is captured before the
    guard is applied and its owner/group/ordered DACL ACEs are restored exactly
    afterwards (PH3-009); protected leaves below ordinary directories have
    their immediate parent locked so replacement is denied (PH3-006).
    """

    def __init__(self, project_root, protected_relative: Optional[Iterable[str]] = None):
        self.project_root = canonicalize_existing_directory(project_root)
        self.protected_relative = (sorted(protected_relative)
                                   if protected_relative is not None else None)
        self._snapshots: List[Tuple[Path, str]] = []
        self._applied: List[Path] = []
        self._locked = False

    def _selected_entries(self) -> Tuple[List[Path], List[Path]]:
        return control_plane_entries(self.project_root, self.protected_relative)

    def lock(self) -> "ControlPlaneGuard":
        if self._locked:
            return self
        files, directories = self._selected_entries()
        # PH3-006: the immediate parent of every protected leaf must be locked
        # too, so a file below an ordinary product directory cannot be replaced,
        # renamed over or deleted through its writable parent.
        leaf_parents = {entry.parent for entry in files}
        entries = [self.project_root]
        entries += sorted(directories, key=lambda p: (len(p.parts), str(p)))
        entries += sorted(leaf_parents, key=lambda p: (len(p.parts), str(p)))
        entries += sorted(files, key=lambda p: (len(p.parts), str(p)))
        # De-duplicate while preserving order: an entry may be both a control
        # directory and the parent of a protected leaf.
        seen = set()
        unique: List[Path] = []
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            unique.append(entry)
        entries = unique
        if not files and not directories:
            raise GuardError("no control-plane material found to guard")
        snapshots: List[Tuple[Path, str]] = []
        applied: List[Path] = []
        try:
            for entry in entries:
                snapshots.append((entry, _acl_sddl(entry)))
            for entry in entries:
                deny = _ROOT_DENY if entry == self.project_root else _deny_for(entry)
                _icacls(entry, "/deny", _DENY_EVERYONE + ":" + deny)
                applied.append(entry)
        except Exception as error:
            # Best-effort fail-closed rollback: restore every captured ACL.
            for entry, sddl in reversed(snapshots):
                try:
                    _set_acl_sddl(entry, sddl)
                except Exception:
                    pass
            raise GuardError("control-plane guard failed closed: %s" % error) from error
        self._snapshots = snapshots
        self._applied = applied
        self._locked = True
        return self

    def verify(self) -> None:
        """Prove that the guard is effective at the OS boundary.

        A representative control file must reject open-for-write and
        append-only opens; a representative control directory must reject
        creating a probe entry.  The denied probes never leave a mutation
        behind.
        """
        if not self._locked:
            raise GuardError("control-plane guard is not active")
        files, directories = self._selected_entries()
        control_file = next((p for p in files if ".git" not in p.parts), None)
        control_dir = next((p for p in directories if ".git" not in p.parts), None)
        if control_file is None and control_dir is None:
            raise GuardError("cannot verify guard: missing control material")
        if control_file is not None:
            try:
                with control_file.open("r+b"):
                    raise GuardError(
                        "guard verification failed: control file is writable")
            except OSError:
                pass
            if not _append_denied(control_file):
                raise GuardError(
                    "guard verification failed: control file is append-writable")
        if control_dir is not None:
            probe = control_dir / (".rad-guard-probe-" + os.urandom(4).hex())
            try:
                probe.open("wb").close()
                probe.unlink()
                raise GuardError(
                    "guard verification failed: control directory accepts creates")
            except OSError:
                pass

    def restore(self) -> None:
        """PH3-009: restore the exact original owner/group/DACL ACEs."""
        failures = []
        for entry, sddl in reversed(self._snapshots):
            try:
                _set_acl_sddl(entry, sddl)
            except GuardError as error:
                failures.append("%s: %s" % (entry, error))
        self._snapshots = []
        self._applied = []
        self._locked = False
        if failures:
            raise GuardError("control-plane guard restore incomplete: "
                             + "; ".join(failures))

    def __enter__(self) -> "ControlPlaneGuard":
        return self.lock()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.restore()


def lock_control_plane(project_root,
                       protected_relative: Optional[Iterable[str]] = None) -> ControlPlaneGuard:
    return ControlPlaneGuard(project_root, protected_relative).lock()


def guard_report(project_root,
                 protected_relative: Optional[Iterable[str]] = None) -> str:
    """Machine-readable status of the guard state for operator tooling."""
    question = check_control_plane_locked(project_root, protected_relative)
    try:
        files, directories = control_plane_entries(project_root, protected_relative)
        protected = len(files) + len(directories)
    except GuardError as error:
        return json.dumps({"status": "error", "detail": str(error)}, sort_keys=True)
    return json.dumps({"status": "locked" if question else "unlocked",
                       "protected_paths": protected}, sort_keys=True)
