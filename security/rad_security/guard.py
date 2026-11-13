"""Windows ACL-based session guard for the target control plane.

The authoritative RAD control plane lives in the installed, externally pinned
release outside the target workspace.  The repository copy of control material
(``AGENTS.md``, ``.rad/**``, adapters, generator, ``DECISIONS.md`` and similar)
is untrusted project data in Secure Mode: it must never become authority.

This module provides a reversible, per-session OS boundary that denies the
guarded mutation rights to the launch token and its subsequently opened
descendant handles.  Denial is enforced by the Windows security descriptor,
not by agent instruction or file naming.  Rights already granted through an
open handle are not revoked by a later DACL change, and a same-account owner
can retain WRITE_DAC; those Windows limits are part of the documented residual
risk rather than capabilities this guard claims to remove.

Phase 4 hardening applied here:

- PH3-001: helper executables such as ``icacls.exe`` are resolved from the
  canonical trusted system directory, never via PATH or the current directory.
  Native ACL APIs are loaded from ``System32`` with restricted DLL search.
- PH3-005: the deny masks explicitly cover `FILE_APPEND_DATA` (AD),
  `FILE_WRITE_ATTRIBUTES` (WA), `FILE_WRITE_EA` (WEA), write-data (WD) and
  delete (DE), plus delete-child (DC) where required for directory/name-entry
  protection. `WRITE_DAC` and `WRITE_OWNER` remain outside the mask so exact
  restoration stays possible; same-owner DACL replacement is a documented
  residual that requires a separate-principal backend to close.
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
from typing import Dict, Iterable, List, Optional, Tuple

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


def _control_plane_entries_with_identity(
        project_root, protected_relative: Optional[Iterable[str]] = None,
        ) -> Tuple[List[Path], List[Path], Dict[Path, Tuple[int, int]]]:
    """Enumerate guarded entries and their NTFS volume/file identities.

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
    identities: Dict[Path, Tuple[int, int]] = {}
    try:
        root_info = root.lstat()
    except OSError as error:
        raise GuardError("control-plane guard cannot inspect root: category=%s" %
                         type(error).__name__) from error
    identities[root] = (int(root_info.st_dev) & 0xffffffff,
                        int(root_info.st_ino))
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
            identities[child] = (int(info.st_dev) & 0xffffffff,
                                 int(info.st_ino))
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
    return files, directories, identities


def control_plane_entries(project_root, protected_relative: Optional[Iterable[str]] = None,
                          ) -> Tuple[List[Path], List[Path]]:
    """Return the guarded files and directories under a canonical root."""
    files, directories, _identities = _control_plane_entries_with_identity(
        project_root, protected_relative)
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
_SE_DACL_PRESENT = 0x0004
_SE_DACL_AUTO_INHERIT_REQ = 0x0100
_SE_DACL_AUTO_INHERITED = 0x0400
_SECURITY_DESCRIPTOR_REVISION = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_SE_FILE_OBJECT = 1
_MAXIMUM_ALLOWED = 0x02000000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_WRITE_EA = 0x00000010
_FILE_WRITE_ATTRIBUTES = 0x00000100
_DELETE = 0x00010000
_FILE_DELETE_CHILD = 0x00000040
_FILE_DENY_MASK = (_FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_WRITE_EA
                   | _FILE_WRITE_ATTRIBUTES | _DELETE)
_DIR_DENY_MASK = _FILE_DENY_MASK | _FILE_DELETE_CHILD
_ROOT_DENY_MASK = _FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_DELETE_CHILD

_TOKEN_DUPLICATE = 0x0002
_TOKEN_QUERY = 0x0008
_SECURITY_IMPERSONATION = 2
_ERROR_NO_TOKEN = 1008
_SYNCHRONIZE = 0x00100000
_FILE_READ_DATA = 0x00000001
_FILE_READ_EA = 0x00000008
_FILE_EXECUTE = 0x00000020
_FILE_READ_ATTRIBUTES = 0x00000080
_STANDARD_RIGHTS_REQUIRED = 0x000F0000


class _ByHandleFileInformation(ctypes.Structure):
    """BY_HANDLE_FILE_INFORMATION as returned by a documented Win32 API."""

    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_low", ctypes.c_uint32),
        ("creation_high", ctypes.c_uint32),
        ("access_low", ctypes.c_uint32),
        ("access_high", ctypes.c_uint32),
        ("write_low", ctypes.c_uint32),
        ("write_high", ctypes.c_uint32),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _TrusteeW(ctypes.Structure):
    _fields_ = [
        ("multiple_trustee", ctypes.c_void_p),
        ("multiple_trustee_operation", ctypes.c_uint32),
        ("trustee_form", ctypes.c_uint32),
        ("trustee_type", ctypes.c_uint32),
        ("name", ctypes.c_void_p),
    ]


class _ExplicitAccessW(ctypes.Structure):
    _fields_ = [
        ("access_permissions", ctypes.c_uint32),
        ("access_mode", ctypes.c_uint32),
        ("inheritance", ctypes.c_uint32),
        ("trustee", _TrusteeW),
    ]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("ace_count", ctypes.c_uint32),
        ("bytes_in_use", ctypes.c_uint32),
        ("bytes_free", ctypes.c_uint32),
    ]


_ACL_SIZE_INFORMATION = 2


class _GenericMapping(ctypes.Structure):
    _fields_ = [
        ("generic_read", ctypes.c_uint32),
        ("generic_write", ctypes.c_uint32),
        ("generic_execute", ctypes.c_uint32),
        ("generic_all", ctypes.c_uint32),
    ]


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


def _local_free_all(kernel, *allocations) -> None:
    """Release every LocalAlloc result and fail if Windows reports a leak."""
    failures = []
    for allocation in allocations:
        if not allocation:
            continue
        ctypes.set_last_error(0)
        if kernel.LocalFree(allocation):
            failures.append(_security_error("LocalFree", ctypes.get_last_error()))
    if failures:
        raise GuardError("security allocation release failed: "
                         + "; ".join(str(failure) for failure in failures))


@lru_cache(maxsize=1)
def _security_apis():
    """Load native ACL APIs from trusted Windows system libraries."""
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
    advapi.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorGroup.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorGroup.restype = wintypes.BOOL
    advapi.IsValidSecurityDescriptor.argtypes = [ctypes.c_void_p]
    advapi.IsValidSecurityDescriptor.restype = wintypes.BOOL
    advapi.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi.IsValidSid.restype = wintypes.BOOL
    advapi.IsValidAcl.argtypes = [ctypes.c_void_p]
    advapi.IsValidAcl.restype = wintypes.BOOL
    advapi.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.SetSecurityInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    advapi.SetEntriesInAclW.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.SetEntriesInAclW.restype = wintypes.DWORD
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.OpenThreadToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenThreadToken.restype = wintypes.BOOL
    advapi.DuplicateToken.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.DuplicateToken.restype = wintypes.BOOL
    advapi.AccessCheck.argtypes = [
        ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD,
        ctypes.POINTER(_GenericMapping), ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.AccessCheck.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
    ]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentThread.argtypes = []
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    return advapi, kernel


def _system_dll(name: str) -> Path:
    """Return a trusted DLL path under the resolved Windows System32."""
    return _system_root() / "System32" / name


def _capture_security_descriptor_sddl(path: Path) -> str:
    return _capture_security_descriptor_state(path)[0]


def _capture_security_descriptor_state(path: Path) -> Tuple[str, int]:
    """Capture owner/group/DACL SDDL and the returned control word together.

    Keep GetFileSecurityW for the saved representation: a temp-tree experiment
    showed GetSecurityInfo can report inherited ACE markers differently from
    this path-based descriptor. Guard callers hold an identity-checked handle
    and pinned parents around this capture. The control word belongs to this
    requested owner/group/DACL descriptor; this function does not request or
    snapshot SACL data.
    """
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

    _owner, _group, _dacl, control = _validate_security_descriptor(descriptor)

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
            _local_free_all(kernel, ctypes.cast(sddl_pointer, ctypes.c_void_p))
    if not sddl or not sddl.startswith("O:"):
        raise GuardError("security descriptor conversion returned empty or invalid SDDL")
    # Validate the transported form too. This catches any loss of a required
    # component or relevant DACL control bit before the snapshot is trusted.
    _validate_sddl_snapshot(sddl, control)
    return sddl, control


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


def _open_security_handle(path: Path, desired_access: int, share_mode: int,
                          expected_identity: Optional[Tuple[int, int]] = None,
                          reject_hardlinks: bool = False):
    """Open one NTFS object without following its final reparse point.

    The returned identity is (volume serial, 64-bit file index). The caller
    must keep the handle while relying on that identity.
    """
    _advapi, kernel = _security_apis()
    try:
        before = Path(path).lstat()
    except OSError as error:
        raise GuardError("cannot inspect ACL target: category=%s" %
                         type(error).__name__) from error
    before_attributes = getattr(before, "st_file_attributes", 0)
    if stat.S_ISLNK(before.st_mode) or before_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise GuardError("linked or reparse ACL target refused")
    if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
        raise GuardError("special ACL target refused")

    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if stat.S_ISDIR(before.st_mode):
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel.CreateFileW(
        str(path), desired_access, share_mode, None, _OPEN_EXISTING, flags, None)
    if handle == _INVALID_HANDLE_VALUE or not handle:
        raise _security_error("CreateFileW", ctypes.get_last_error())
    try:
        information = _ByHandleFileInformation()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise _security_error("GetFileInformationByHandle",
                                  ctypes.get_last_error())
        identity = (int(information.volume_serial),
                    (int(information.file_index_high) << 32)
                    | int(information.file_index_low))
        expected_from_path = (int(before.st_dev) & 0xffffffff,
                              int(before.st_ino))
        if identity != expected_from_path or (
                expected_identity is not None and identity != expected_identity):
            raise GuardError("ACL target identity changed during capture")
        if information.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise GuardError("linked or reparse ACL target refused")
        is_directory = bool(information.attributes & _FILE_ATTRIBUTE_DIRECTORY)
        if is_directory != stat.S_ISDIR(before.st_mode):
            raise GuardError("ACL target type changed during capture")
        if reject_hardlinks and not is_directory and information.link_count != 1:
            raise GuardError("hardlinked ACL target refused")
        return handle, identity, information
    except Exception as error:
        if not kernel.CloseHandle(handle):
            cleanup_error = _security_error("CloseHandle", ctypes.get_last_error())
            cleanup_error.recovery_handle = handle
            cleanup_error.recovery_path = Path(path)
            raise cleanup_error from error
        raise


def _identity_from_handle(handle) -> Tuple[Tuple[int, int], _ByHandleFileInformation]:
    """Read the stable volume/file identity of an already-open handle."""
    kernel = _security_apis()[1]
    information = _ByHandleFileInformation()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise _security_error("GetFileInformationByHandle",
                              ctypes.get_last_error())
    identity = (int(information.volume_serial),
                (int(information.file_index_high) << 32)
                | int(information.file_index_low))
    if information.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise GuardError("linked or reparse ACL target refused")
    return identity, information


def _path_identity(path: Path) -> Tuple[int, int]:
    """Read and validate the final path component's current NTFS identity."""
    try:
        info = Path(path).lstat()
    except OSError as error:
        raise GuardError("cannot inspect ACL target: category=%s" %
                         type(error).__name__) from error
    attributes = getattr(info, "st_file_attributes", 0)
    if (stat.S_ISLNK(info.st_mode)
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
        raise GuardError("linked, reparse, or special ACL target refused")
    return int(info.st_dev) & 0xffffffff, int(info.st_ino)


def _close_security_handle(handle) -> None:
    if not _security_apis()[1].CloseHandle(handle):
        raise _security_error("CloseHandle", ctypes.get_last_error())


def _handle_security_descriptor(handle):
    """Return an allocated owner/group/DACL descriptor for one open handle."""
    advapi, _kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    information = (_OWNER_SECURITY_INFORMATION | _GROUP_SECURITY_INFORMATION
                   | _DACL_SECURITY_INFORMATION)
    error_code = advapi.GetSecurityInfo(
        handle, _SE_FILE_OBJECT, information, None, None, None, None,
        ctypes.byref(descriptor))
    if error_code:
        _local_free_all(_security_apis()[1], descriptor)
        raise _security_error("GetSecurityInfo", error_code)
    if not descriptor:
        raise GuardError("GetSecurityInfo returned an empty descriptor")
    return descriptor


def _descriptor_control(descriptor) -> int:
    advapi, _kernel = _security_apis()
    control = ctypes.c_uint16(0)
    revision = ctypes.c_uint32(0)
    if not advapi.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)):
        raise _security_error("GetSecurityDescriptorControl",
                              ctypes.get_last_error())
    return int(control.value)


def _validate_sid_pointer(advapi, sid, component: str) -> None:
    """Reject missing or malformed native SID outputs without logging data."""
    if not sid:
        raise GuardError(
            "cannot restore security descriptor: missing %s" % component)
    if not advapi.IsValidSid(sid):
        raise GuardError(
            "cannot restore security descriptor: invalid %s SID" % component)


def _validate_acl_pointer(advapi, acl, component: str = "DACL") -> None:
    """Reject NULL, malformed and empty native ACL outputs before mutation."""
    if not acl:
        raise GuardError(
            "cannot restore security descriptor: NULL %s refused" % component)
    if not advapi.IsValidAcl(acl):
        raise GuardError(
            "cannot restore security descriptor: invalid %s" % component)
    acl_size = _AclSizeInformation()
    if not advapi.GetAclInformation(
            acl, ctypes.byref(acl_size), ctypes.sizeof(acl_size),
            _ACL_SIZE_INFORMATION):
        raise _security_error("GetAclInformation", ctypes.get_last_error())
    if acl_size.ace_count == 0:
        raise GuardError(
            "cannot restore security descriptor: empty %s refused" % component)


def _validate_security_descriptor(
        descriptor, expected_control: Optional[int] = None,
        ) -> Tuple[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, int]:
    """Validate the exact Owner/Group/DACL restore payload before mutation.

    A missing DACL and an explicitly NULL DACL are distinct native states, but
    either would make a RAD lock/restore unsafe. A non-NULL zero-ACE ACL is
    structurally valid, but is also refused: the AI-clear path setter cannot
    be relied on to reopen that object for exact recovery after access is
    removed. No descriptor content is included in diagnostics.
    """
    from ctypes import wintypes

    advapi, _kernel = _security_apis()
    if not descriptor or not advapi.IsValidSecurityDescriptor(descriptor):
        raise GuardError("cannot restore security descriptor: invalid descriptor")

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    present = wintypes.BOOL(0)
    defaulted = wintypes.BOOL(0)
    if not advapi.GetSecurityDescriptorOwner(
            descriptor, ctypes.byref(owner), ctypes.byref(defaulted)):
        raise _security_error("GetSecurityDescriptorOwner",
                              ctypes.get_last_error())
    _validate_sid_pointer(advapi, owner, "owner")
    if not advapi.GetSecurityDescriptorGroup(
            descriptor, ctypes.byref(group), ctypes.byref(defaulted)):
        raise _security_error("GetSecurityDescriptorGroup",
                              ctypes.get_last_error())
    _validate_sid_pointer(advapi, group, "group")
    if not advapi.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl),
            ctypes.byref(defaulted)):
        raise _security_error("GetSecurityDescriptorDacl",
                              ctypes.get_last_error())

    control = _descriptor_control(descriptor)
    control_present = bool(control & _SE_DACL_PRESENT)
    if bool(present.value) != control_present:
        raise GuardError(
            "cannot restore security descriptor: inconsistent DACL presence")
    if not present.value:
        raise GuardError("cannot restore security descriptor: missing DACL")
    _validate_acl_pointer(advapi, dacl)
    if (expected_control is not None
            and control != (int(expected_control) & 0xffff)):
        raise GuardError(
            "cannot restore security descriptor: inconsistent DACL control state")
    return owner, group, dacl, control


def _convert_and_validate_descriptor(
        sddl: str, expected_control: Optional[int] = None,
        ) -> Tuple[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, int]:
    """Convert an SDDL snapshot and validate all required components.

    The returned descriptor is LocalAlloc-owned by the caller. Every error path
    frees it here, before a setter can be reached.
    """
    from ctypes import wintypes

    if not isinstance(sddl, str) or not sddl:
        raise GuardError("cannot restore security descriptor: invalid SDDL")
    advapi, kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD(0)
    try:
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, _SECURITY_DESCRIPTOR_REVISION, ctypes.byref(descriptor),
                ctypes.byref(descriptor_size)):
            raise _security_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                ctypes.get_last_error())
        if not descriptor or not descriptor_size.value:
            raise GuardError(
                "cannot restore security descriptor: empty converted descriptor")
        owner, group, dacl, control = _validate_security_descriptor(
            descriptor, expected_control)
        return descriptor, owner, group, dacl, control
    except Exception:
        if descriptor:
            _local_free_all(kernel, descriptor)
        raise


def _validate_sddl_snapshot(sddl: str, expected_control: int) -> None:
    """Validate one trusted snapshot without mutating any securable object."""
    descriptor = ctypes.c_void_p()
    kernel = _security_apis()[1]
    try:
        descriptor, _owner, _group, _dacl, _control = (
            _convert_and_validate_descriptor(sddl, expected_control))
    finally:
        if descriptor:
            _local_free_all(kernel, descriptor)


def _set_descriptor_on_handle(
        handle, sddl: str, expected_control: Optional[int] = None) -> None:
    """Set the captured owner, group and DACL through a stable handle."""
    advapi, kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    try:
        descriptor, owner, group, dacl, control = (
            _convert_and_validate_descriptor(sddl, expected_control))
        security_information = (_OWNER_SECURITY_INFORMATION
                                | _GROUP_SECURITY_INFORMATION
                                | _DACL_SECURITY_INFORMATION)
        if control & _SE_DACL_PROTECTED:
            security_information |= _PROTECTED_DACL_SECURITY_INFORMATION
        else:
            security_information |= _UNPROTECTED_DACL_SECURITY_INFORMATION
        error_code = advapi.SetSecurityInfo(
            handle, _SE_FILE_OBJECT, security_information, owner, group,
            dacl, None)
        if error_code:
            raise _security_error("SetSecurityInfo", error_code)
    finally:
        if descriptor:
            _local_free_all(kernel, descriptor)


def _set_descriptor_by_path(
        path: Path, sddl: str, expected_control: Optional[int] = None) -> None:
    """Restore an AI-clear descriptor without invoking auto-inheritance."""
    advapi, kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    try:
        descriptor, _owner, _group, _dacl, control = (
            _convert_and_validate_descriptor(sddl, expected_control))
        security_information = (_OWNER_SECURITY_INFORMATION
                               | _GROUP_SECURITY_INFORMATION
                               | _DACL_SECURITY_INFORMATION)
        if control & _SE_DACL_PROTECTED:
            security_information |= _PROTECTED_DACL_SECURITY_INFORMATION
        else:
            security_information |= _UNPROTECTED_DACL_SECURITY_INFORMATION
        ctypes.set_last_error(0)
        if not advapi.SetFileSecurityW(str(path), security_information, descriptor):
            raise _security_error("SetFileSecurityW", ctypes.get_last_error())
    finally:
        if descriptor:
            _local_free_all(kernel, descriptor)


def _add_guard_deny_on_handle(handle, access_mask: int) -> None:
    """Add an explicit Everyone deny ACE without changing descendant ACLs."""
    advapi, kernel = _security_apis()
    descriptor = _handle_security_descriptor(handle)
    sid = ctypes.c_void_p()
    new_acl = ctypes.c_void_p()
    try:
        _owner, _group, old_acl, control = _validate_security_descriptor(
            descriptor)
        if not advapi.ConvertStringSidToSidW("S-1-1-0", ctypes.byref(sid)):
            raise _security_error("ConvertStringSidToSidW",
                                  ctypes.get_last_error())
        _validate_sid_pointer(advapi, sid, "guard trustee")
        entry = _ExplicitAccessW(
            access_mask, 3, 0,
            _TrusteeW(None, 0, 0, 5, ctypes.cast(sid, ctypes.c_void_p)))
        error_code = advapi.SetEntriesInAclW(
            1, ctypes.byref(entry), old_acl,
            ctypes.byref(new_acl))
        if error_code:
            raise _security_error("SetEntriesInAclW", error_code)
        _validate_acl_pointer(advapi, new_acl, "generated DACL")
        security_information = _DACL_SECURITY_INFORMATION
        if control & _SE_DACL_PROTECTED:
            security_information |= _PROTECTED_DACL_SECURITY_INFORMATION
        else:
            security_information |= _UNPROTECTED_DACL_SECURITY_INFORMATION
        error_code = advapi.SetSecurityInfo(
            handle, _SE_FILE_OBJECT, security_information,
            None, None, new_acl, None)
        if error_code:
            raise _security_error("SetSecurityInfo", error_code)
    finally:
        _local_free_all(kernel, new_acl, sid, descriptor)


def _restore_security_descriptor_sddl(path: Path, sddl: str) -> None:
    """Restore one SDDL snapshot using the API matching its AI state.

    SetSecurityInfo converts unprotected descriptors to the current automatic
    inheritance model. SetFileSecurityW is retained only for snapshots whose
    captured DACL has AI clear; this preserves that exact legacy control state
    and does not propagate ACL changes to descendants. The caller holds an
    identity-checked handle while this path-based setter runs.
    """
    handle = None
    try:
        handle, _identity, _info = _open_security_handle(
            Path(path), _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE)
        descriptor = ctypes.c_void_p()
        descriptor_size = ctypes.c_uint32(0)
        advapi, kernel = _security_apis()
        try:
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, _SECURITY_DESCRIPTOR_REVISION,
                    ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
                raise _security_error(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                    ctypes.get_last_error())
            _owner, _group, _dacl, control = _validate_security_descriptor(
                descriptor)
        finally:
            _local_free_all(kernel, descriptor)
        if control & _SE_DACL_AUTO_INHERITED:
            _set_descriptor_on_handle(handle, sddl, control)
        else:
            _set_descriptor_by_path(Path(path), sddl, control)
    finally:
        if handle:
            try:
                _close_security_handle(handle)
            except GuardError as error:
                error.recovery_handle = handle
                error.recovery_path = Path(path)
                raise


def _set_acl_sddl(path: Path, sddl: str) -> None:
    """Restore and verify the exact captured owner/group/DACL on one object."""
    if not isinstance(sddl, str) or not sddl or not sddl.startswith("O:"):
        raise GuardError("cannot restore security descriptor: invalid SDDL")
    handle = None
    try:
        handle, _identity, _info = _open_security_handle(
            Path(path), _MAXIMUM_ALLOWED,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE)
        _restore_security_descriptor_sddl(Path(path), sddl)
        actual = _capture_security_descriptor_sddl(Path(path))
        if not _same_restored_acl(sddl, actual):
            raise GuardError("restored ACL does not match captured owner/group/DACL")
    except GuardError:
        raise
    except OSError as error:
        raise GuardError("cannot restore security descriptor: category=%s" %
                         type(error).__name__) from error
    finally:
        if handle:
            try:
                _close_security_handle(handle)
            except GuardError as error:
                error.recovery_handle = handle
                error.recovery_path = Path(path)
                raise


def _restore_security_descriptor_sddl_on_handle(
        handle, sddl: str, path: Path, original_control: int) -> None:
    """Restore through the identity-bound handle or its pinned pathname."""
    if original_control & _SE_DACL_AUTO_INHERITED:
        _set_descriptor_on_handle(handle, sddl, original_control)
    else:
        _set_descriptor_by_path(path, sddl, original_control)


def _same_restored_acl(expected: str, actual: str) -> bool:
    """Compare the complete captured SDDL without normalizing any control bit."""
    return expected == actual


def _deny_for(entry: Path) -> str:
    return _DIR_DENY if entry.is_dir() else _FILE_DENY


def check_control_plane_locked(project_root,
                               protected_relative: Optional[Iterable[str]] = None) -> bool:
    """Read DACLs and prove every guarded right is denied to this token."""
    files, directories, identities = _control_plane_entries_with_identity(
        project_root, protected_relative)
    if not files and not directories:
        return False
    root = canonicalize_existing_directory(project_root)
    leaf_parents = {entry.parent for entry in files}
    entries = [root]
    entries += sorted(directories, key=lambda p: (len(p.parts), str(p)))
    entries += sorted(leaf_parents, key=lambda p: (len(p.parts), str(p)))
    entries += sorted(files, key=lambda p: (len(p.parts), str(p)))
    opened = []
    seen = set()
    try:
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            expected = identities.get(entry)
            if expected is None:
                raise GuardError("missing enumerated verifier target identity")
            handle, identity, information = _open_security_handle(
                entry, _READ_CONTROL,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
                expected_identity=expected, reject_hardlinks=True)
            if identity != expected:
                raise GuardError("verifier target identity changed")
            opened.append((entry, handle, bool(
                information.attributes & _FILE_ATTRIBUTE_DIRECTORY)))
        for entry, handle, is_directory in opened:
            denied = (_ROOT_DENY_MASK if entry == root
                      else (_DIR_DENY_MASK if is_directory
                            else _FILE_DENY_MASK))
            for right in _mask_bits(denied):
                if _current_token_has_file_access(handle, right):
                    return False
        return True
    finally:
        failures = []
        kernel = _security_apis()[1]
        for _entry, handle, _is_directory in reversed(opened):
            if not kernel.CloseHandle(handle):
                failures.append(str(_security_error(
                    "CloseHandle", ctypes.get_last_error())))
        if failures:
            raise GuardError("verifier handle release incomplete: "
                             + "; ".join(failures))


def _mask_bits(mask: int) -> Iterable[int]:
    """Yield rights separately so one denied bit cannot hide an allowed bit."""
    bit = 1
    while bit <= mask:
        if mask & bit:
            yield bit
        bit <<= 1


def _current_token_has_file_access(handle, desired_access: int) -> bool:
    """Run AccessCheck over the current DACL/token without filesystem writes."""
    from ctypes import wintypes

    advapi, kernel = _security_apis()
    descriptor = ctypes.c_void_p()
    primary = wintypes.HANDLE()
    impersonation = wintypes.HANDLE()
    access_allowed = False
    primary_error = None
    try:
        descriptor = _handle_security_descriptor(handle)
        ctypes.set_last_error(0)
        if not advapi.OpenThreadToken(
                kernel.GetCurrentThread(), _TOKEN_QUERY | _TOKEN_DUPLICATE,
                True, ctypes.byref(primary)):
            if ctypes.get_last_error() != _ERROR_NO_TOKEN:
                raise _security_error("OpenThreadToken", ctypes.get_last_error())
            if not advapi.OpenProcessToken(
                    kernel.GetCurrentProcess(), _TOKEN_QUERY | _TOKEN_DUPLICATE,
                    ctypes.byref(primary)):
                raise _security_error("OpenProcessToken", ctypes.get_last_error())
        if not advapi.DuplicateToken(
                primary, _SECURITY_IMPERSONATION,
                ctypes.byref(impersonation)):
            raise _security_error("DuplicateToken", ctypes.get_last_error())
        mapping = _GenericMapping(
            _READ_CONTROL | _SYNCHRONIZE | _FILE_READ_DATA
            | _FILE_READ_EA | _FILE_READ_ATTRIBUTES,
            _READ_CONTROL | _SYNCHRONIZE | _FILE_WRITE_DATA
            | _FILE_APPEND_DATA | _FILE_WRITE_EA | _FILE_WRITE_ATTRIBUTES,
            _READ_CONTROL | _SYNCHRONIZE | _FILE_EXECUTE
            | _FILE_READ_ATTRIBUTES,
            _STANDARD_RIGHTS_REQUIRED | _SYNCHRONIZE | 0x1FF,
        )
        privilege_size = wintypes.DWORD(0)
        granted = wintypes.DWORD(0)
        access_status = wintypes.BOOL(False)
        ctypes.set_last_error(0)
        first = advapi.AccessCheck(
            descriptor, impersonation, desired_access,
            ctypes.byref(mapping), None, ctypes.byref(privilege_size),
            ctypes.byref(granted), ctypes.byref(access_status))
        if first:
            access_allowed = bool(access_status.value)
        else:
            if (ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
                    or not 0 < privilege_size.value <= 1024 * 1024):
                raise _security_error("AccessCheck", ctypes.get_last_error())
            privileges = ctypes.create_string_buffer(privilege_size.value)
            ctypes.set_last_error(0)
            if not advapi.AccessCheck(
                    descriptor, impersonation, desired_access,
                    ctypes.byref(mapping), privileges,
                    ctypes.byref(privilege_size), ctypes.byref(granted),
                    ctypes.byref(access_status)):
                raise _security_error("AccessCheck", ctypes.get_last_error())
            access_allowed = bool(access_status.value)
    except BaseException as error:
        primary_error = error
    finally:
        failures = []
        try:
            _local_free_all(kernel, descriptor)
        except GuardError as error:
            failures.append(str(error))
        for handle in (impersonation, primary):
            if handle and not kernel.CloseHandle(handle):
                failures.append(str(_security_error(
                    "CloseHandle", ctypes.get_last_error())))
        if failures:
            cleanup_error = GuardError(
                "access-check handle release incomplete: "
                + "; ".join(failures))
            cleanup_error.primary_error = primary_error
            if primary_error is not None:
                raise cleanup_error from primary_error
            raise cleanup_error
    if primary_error is not None:
        raise primary_error
    return access_allowed


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
    """Refuse snapshot-free removal of installation hardening ACLs."""
    del install_root
    raise GuardError(
        "installation unharden refused: no trusted original ACL snapshot is "
        "available; use an independently trusted backup or reinstall into a "
        "new reviewed destination")


def unlock_control_plane(project_root,
                         protected_relative: Optional[Iterable[str]] = None) -> int:
    """Refuse snapshot-free recovery of a control-plane guard.

    Exact restoration requires the trusted in-memory snapshot owned by the
    live ``ControlPlaneGuard``.  Guessing by deleting Everyone deny ACEs can
    weaken authorization that existed before RAD, so this API always fails
    before inspecting or mutating the project.
    """
    del project_root, protected_relative
    raise GuardError(
        "standalone unlock refused: no trusted original ACL snapshot is "
        "available; use an independently trusted backup or manually reviewed "
        "recovery")


class ControlPlaneGuard:
    """Reversible per-session mutex against repository control-plane writes.

    Usage::

        with lock_control_plane(project) as guard:
            guard.verify()   # raises unless truly denied at the OS boundary
            ... run the runtime / descendants ...
        # exiting restores the exact original owner/group/ordered DACL ACEs.

    PH3-009: exact owner/group/DACL SDDL and the full control word returned
    with that requested descriptor are captured with GetFileSecurityW while the corresponding
    identity-checked handle is held. Restore handles stay open for the session;
    they and ancestor handles pin paths while any AI-clear SDDL restore uses
    SetFileSecurityW.
    """

    def __init__(self, project_root, protected_relative: Optional[Iterable[str]] = None):
        self.project_root = canonicalize_existing_directory(project_root)
        self.protected_relative = (sorted(protected_relative)
                                   if protected_relative is not None else None)
        self._snapshots: List[Tuple[Path, str]] = []
        self._applied: List[Path] = []
        self._identities: Dict[Path, Tuple[int, int]] = {}
        self._dacl_controls: Dict[Path, int] = {}
        self._restore_handles: Dict[Path, object] = {}
        self._pinned_handles: Dict[Path, object] = {}
        self._locked = False

    def _selected_entries(self) -> Tuple[List[Path], List[Path]]:
        return control_plane_entries(self.project_root, self.protected_relative)

    def lock(self) -> "ControlPlaneGuard":
        if self._locked:
            return self
        files, directories, identities = _control_plane_entries_with_identity(
            self.project_root, self.protected_relative)
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
        self._identities = identities
        target_entries = set(entries)
        capture_handles: Dict[Path, Tuple[object, bool, Tuple[int, int]]] = {}
        try:
            # Pin the target's parent directory so the project-root name cannot
            # be replaced while the in-process guard owns its handles.
            self._pin_ancestor(self.project_root.parent, required=False)
            for entry in entries:
                self._pin_entry_ancestors(
                    entry, target_entries, set(capture_handles))
                expected_identity = identities.get(entry)
                if expected_identity is None:
                    raise GuardError("missing enumerated ACL target identity")
                is_directory = stat.S_ISDIR(entry.lstat().st_mode)
                # Directory enumeration remains available through read
                # sharing.  This denies subsequent opens requesting write/data
                # or delete sharing. It cannot revoke FILE_WRITE_ATTRIBUTES
                # already granted by a pre-existing handle.
                share_mode = _FILE_SHARE_READ
                handle, identity, _info = _open_security_handle(
                    entry, _MAXIMUM_ALLOWED,
                    share_mode, expected_identity=expected_identity,
                    reject_hardlinks=True)
                capture_handles[entry] = (handle, is_directory, identity)
                if _path_identity(entry) != identity:
                    raise GuardError("ACL target identity changed before capture")
                original_sddl, original_control = (
                    _capture_security_descriptor_state(entry))
                if (_path_identity(entry) != identity
                        or _identity_from_handle(handle)[0] != identity):
                    raise GuardError("ACL target identity changed during capture")
                self._snapshots.append((entry, original_sddl))
                self._identities[entry] = identity
                self._dacl_controls[entry] = original_control

            # This is a transaction precondition: every recovery descriptor is
            # validated before the first SetSecurityInfo call can add a deny.
            self._validate_recovery_snapshots()
            trusted_snapshots = dict(self._snapshots)

            for entry in entries:
                handle, is_directory, identity = capture_handles.pop(entry)
                # Transfer ownership before the native mutation.  This exact
                # MAXIMUM_ALLOWED handle captured the trusted descriptor and
                # remains bound to the same volume/file identity until restore
                # verification succeeds.  There is deliberately no close/open
                # handoff after the deny write.
                self._restore_handles[entry] = handle
                current_sddl, current_control = (
                    _capture_security_descriptor_state(entry))
                if (_identity_from_handle(handle)[0] != identity
                        or _path_identity(entry) != identity):
                    raise GuardError(
                        "ACL target identity changed before lock mutation")
                if (current_sddl != trusted_snapshots[entry]
                        or current_control != self._dacl_controls[entry]):
                    raise GuardError(
                        "ACL target security changed before lock mutation")
                deny_mask = (_ROOT_DENY_MASK if entry == self.project_root
                             else (_DIR_DENY_MASK if is_directory
                                   else _FILE_DENY_MASK))
                # Include the entry in rollback before entering the native
                # mutation call; an ambiguous native failure is restored via
                # the same object-bound handle.
                self._applied.append(entry)
                _add_guard_deny_on_handle(handle, deny_mask)
        except Exception as error:
            # Roll back each partial mutation and verify the exact captured
            # SDDL. Keep snapshots and handles attached to the exception if
            # any rollback step fails so recovery data is not discarded.
            recovery_handle = getattr(error, "recovery_handle", None)
            recovery_path = getattr(error, "recovery_path", None)
            if recovery_handle is not None and recovery_path is not None:
                destination = (self._restore_handles if recovery_path in target_entries
                               else self._pinned_handles)
                destination[recovery_path] = recovery_handle
            close_failures = []
            for path, (handle, _is_directory, _identity) in list(
                    capture_handles.items()):
                if _security_apis()[1].CloseHandle(handle):
                    del capture_handles[path]
                else:
                    self._pinned_handles[path] = handle
                    close_failures.append(str(_security_error(
                        "CloseHandle", ctypes.get_last_error())))
            self._locked = bool(self._applied)
            if not self._locked:
                try:
                    self._close_handles()
                except GuardError as close_error:
                    close_failures.append(str(close_error))
                if close_failures:
                    failure = GuardError(
                        "control-plane guard preflight failed; handle release "
                        "incomplete: " + "; ".join(close_failures))
                    failure.recovery_guard = self
                    raise failure from error
                self._snapshots = []
                self._identities = {}
                self._dacl_controls = {}
                raise GuardError("control-plane guard lock failed closed: %s" %
                                 error) from error
            try:
                self.restore()
            except GuardError as recovery_error:
                failure = GuardError(
                    "control-plane guard lock failed; rollback incomplete: %s" %
                    recovery_error)
                failure.recovery_guard = self
                raise failure from error
            raise GuardError("control-plane guard lock failed closed: %s" %
                             error) from error
        self._locked = True
        return self

    def _pin_ancestor(self, path: Path, required: bool = True) -> None:
        if path in self._restore_handles or path in self._pinned_handles:
            return
        expected = self._identities.get(path)
        if required and expected is None:
            raise GuardError("missing enumerated parent directory identity")
        handle, _identity, _info = _open_security_handle(
            path, _READ_CONTROL, _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            expected_identity=expected)
        self._pinned_handles[path] = handle

    def _pin_entry_ancestors(
            self, entry: Path, targets: set,
            captured_targets: Optional[set] = None) -> None:
        captured_targets = captured_targets or set()
        chain = []
        current = entry.parent
        while current != self.project_root and self.project_root in current.parents:
            chain.append(current)
            current = current.parent
        if entry != self.project_root and current != self.project_root:
            raise GuardError("ACL entry escaped the canonical project root")
        if entry != self.project_root:
            chain.append(self.project_root)
        for ancestor in reversed(chain):
            if ancestor in self._restore_handles or ancestor in self._pinned_handles:
                continue
            if ancestor in targets:
                if ancestor in captured_targets:
                    continue
                raise GuardError("ACL parent was not captured before its child")
            self._pin_ancestor(ancestor)

    def _restore_entry(self, entry: Path, sddl: str) -> None:
        expected = self._identities.get(entry)
        original_control = self._dacl_controls.get(entry)
        if expected is None or original_control is None:
            raise GuardError("missing captured ACL identity or control state")
        handle = self._restore_handles.get(entry)
        if handle is None:
            raise GuardError(
                "missing retained ACL target handle; continuous object "
                "identity cannot be proven")
        current_identity, _info = _identity_from_handle(handle)
        if current_identity != expected or _path_identity(entry) != expected:
            raise GuardError("ACL target identity changed before restore")
        _restore_security_descriptor_sddl_on_handle(
            handle, sddl, entry, original_control)
        actual, actual_control = _capture_security_descriptor_state(entry)
        if (_identity_from_handle(handle)[0] != expected
                or _path_identity(entry) != expected):
            raise GuardError("ACL target identity changed during restore")
        if not _same_restored_acl(sddl, actual):
            raise GuardError("restored ACL does not match the captured SDDL")
        if actual_control != original_control:
            raise GuardError(
                "restored security descriptor control bits do not match "
                "the captured state")

    def _validate_recovery_snapshots(self) -> None:
        """Validate the complete recovery set before any restore mutation."""
        entries = [entry for entry, _sddl in self._snapshots]
        entry_set = set(entries)
        if (len(entries) != len(entry_set)
                or entry_set != set(self._dacl_controls)):
            raise GuardError("incomplete ACL recovery snapshot")
        for entry, sddl in self._snapshots:
            original_control = self._dacl_controls.get(entry)
            if original_control is None:
                raise GuardError("incomplete ACL recovery snapshot")
            _validate_sddl_snapshot(sddl, original_control)
        if (not set(self._applied).issubset(entry_set)
                or any(entry not in self._identities for entry in entry_set)):
            raise GuardError("incomplete ACL recovery snapshot")
        if any(entry not in self._restore_handles for entry in self._applied):
            raise GuardError(
                "incomplete ACL recovery state: missing retained target handle")

    def _close_handles(self) -> None:
        kernel = _security_apis()[1]
        failures = []
        for handle_map in (self._restore_handles, self._pinned_handles):
            for path, handle in list(handle_map.items()):
                if kernel.CloseHandle(handle):
                    del handle_map[path]
                else:
                    failures.append("%s: %s" %
                                    (path, _security_error(
                                        "CloseHandle", ctypes.get_last_error())))
        if failures:
            raise GuardError("control-plane guard handle release incomplete: "
                             + "; ".join(failures))

    def verify(self) -> None:
        """Prove from DACLs that this token lacks every guarded right."""
        if not self._locked:
            raise GuardError("control-plane guard is not active")
        if not check_control_plane_locked(
                self.project_root, self.protected_relative):
            raise GuardError(
                "guard verification failed: current token retains a guarded right")

    def restore(self) -> None:
        """PH3-009: restore and verify captured owner/group/DACL SDDL and control."""
        # Validate the whole recovery transaction before changing the first
        # object. Corrupt or incomplete in-memory recovery data fails closed.
        self._validate_recovery_snapshots()
        failures = []
        applied = set(self._applied)
        for entry, sddl in reversed(self._snapshots):
            if entry not in applied:
                continue
            try:
                self._restore_entry(entry, sddl)
            except GuardError as error:
                recovery_handle = getattr(error, "recovery_handle", None)
                recovery_path = getattr(error, "recovery_path", None)
                if recovery_handle is not None and recovery_path is not None:
                    destination = (self._restore_handles if recovery_path == entry
                                   else self._pinned_handles)
                    destination[recovery_path] = recovery_handle
                failures.append("%s: %s" % (entry, error))
        if failures:
            raise GuardError("control-plane guard restore incomplete: "
                             + "; ".join(failures))
        self._close_handles()
        self._snapshots = []
        self._applied = []
        self._identities = {}
        self._dacl_controls = {}
        self._locked = False

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
