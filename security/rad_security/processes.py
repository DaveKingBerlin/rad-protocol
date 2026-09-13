"""Windows test-process ownership for RAD.

This module is intended to be installed with the trusted RAD launcher.  It must
not be imported from an untrusted target checkout in secure mode.

The security authority is a live Windows Job Object handle held by a guardian
process.  JSON state is authenticated routing data only; it never authorizes a
PID-directed termination.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


SCHEMA = "rad-test-process/v1"
METADATA_FIELDS = {
    "schema",
    "run_id",
    "project_id",
    "project_path",
    "port",
    "guardian_pid",
    "guardian_creation_time",
    "root_pid",
    "listener_pid",
    "control_host",
    "control_port",
    "control_token",
    "state",
    "started_at_unix_ns",
    "failure_code",
}
ENVELOPE_FIELDS = {"payload", "mac"}
CONTROL_HOST = "127.0.0.1"
MAX_CONTROL_MESSAGE = 16 * 1024


class ProcessSecurityError(RuntimeError):
    """A process operation could not be proven safe."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessSecurityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _loads_strict(data: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicate_keys,
                          parse_constant=lambda value: (_ for _ in ()).throw(ProcessSecurityError("non-finite JSON value")))
    except ProcessSecurityError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ProcessSecurityError("invalid JSON") from exc


def canonical_directory(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ProcessSecurityError("process paths must be absolute")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        if part in (".", "..") or ":" in part or part[-1:] in (" ", "."):
            raise ProcessSecurityError("ambiguous process path")
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProcessSecurityError("linked/reparse process path refused")
    candidate = candidate.resolve(strict=True)
    if not candidate.is_dir():
        raise ProcessSecurityError(f"not a directory: {candidate}")
    return candidate


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_trusted_state_paths(project: Path, state_directory: Path, key_file: Path) -> tuple[Path, Path]:
    project = canonical_directory(project)
    if not state_directory.is_absolute() or not key_file.is_absolute():
        raise ProcessSecurityError("state and key paths must be absolute")
    for name in (state_directory.name, key_file.name):
        if not name or name in (".", "..") or any(c in name for c in ':~<>"|?*') or name[-1:] in (" ", "."):
            raise ProcessSecurityError("ambiguous process state name")
    # A trusted operator provisions this parent. Never mkdir through a project
    # link or an unresolved parent supplied in process routing metadata.
    parent = canonical_directory(state_directory.parent)
    state = parent / state_directory.name
    key = key_file
    project_norm = Path(os.path.normcase(str(project)))
    state_norm = Path(os.path.normcase(str(state)))
    key_norm = Path(os.path.normcase(str(key)))
    if _is_relative_to(state_norm, project_norm) or _is_relative_to(key_norm, project_norm):
        raise ProcessSecurityError("trusted process state and key must be outside the untrusted project")
    if Path(os.path.normcase(str(key.parent))) != state_norm:
        raise ProcessSecurityError("the process trust key must be directly inside the trusted state directory")
    if not state.exists():
        state.mkdir(mode=0o700)
    state = canonical_directory(state)
    if key.exists() or key.is_symlink():
        _require_regular_single_link(key)
    return state, key


def _require_regular_single_link(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ProcessSecurityError("linked or non-regular process state refused")


def project_identifier(project: Path) -> str:
    normalized = os.path.normcase(str(project.resolve(strict=True))).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def metadata_path(state_directory: Path, project_id: str, port: int) -> Path:
    return state_directory / f"run-{project_id[:24]}-{port}.json"


def load_or_create_key(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        pass
    else:
        try:
            key = secrets.token_bytes(32)
            if os.write(fd, key) != len(key):
                raise ProcessSecurityError("incomplete process key write")
            os.fsync(fd)
        finally:
            os.close(fd)
    try:
        _require_regular_single_link(path)
        with path.open("rb") as handle:
            key = handle.read(33)
    except OSError as exc:
        raise ProcessSecurityError("unable to read the trusted process key") from exc
    if len(key) != 32:
        raise ProcessSecurityError("trusted process key has an invalid length")
    return key


def load_key(path: Path) -> bytes:
    try:
        _require_regular_single_link(path)
        with path.open("rb") as handle:
            key = handle.read(33)
    except OSError as exc:
        raise ProcessSecurityError("trusted process key is unavailable") from exc
    if len(key) != 32:
        raise ProcessSecurityError("trusted process key has an invalid length")
    return key


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_metadata(payload: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    body = dict(payload)
    return {"payload": body, "mac": hmac.new(key, _canonical_json(body), hashlib.sha256).hexdigest()}


def _validate_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProcessSecurityError(f"invalid {name}")
    return value


def validate_metadata(
    envelope: Any,
    key: bytes,
    *,
    expected_project: Path,
    expected_port: int,
) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ProcessSecurityError("invalid metadata envelope schema")
    payload = envelope.get("payload")
    mac = envelope.get("mac")
    if not isinstance(payload, dict) or set(payload) != METADATA_FIELDS:
        raise ProcessSecurityError("invalid metadata payload schema")
    if not isinstance(mac, str) or not re.fullmatch(r"[0-9a-f]{64}", mac):
        raise ProcessSecurityError("invalid metadata authenticator")
    expected_mac = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ProcessSecurityError("metadata authentication failed")

    if payload["schema"] != SCHEMA:
        raise ProcessSecurityError("unsupported metadata schema")
    if not isinstance(payload["run_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["run_id"]):
        raise ProcessSecurityError("invalid run identity")
    expected_project_id = project_identifier(expected_project)
    if payload["project_id"] != expected_project_id:
        raise ProcessSecurityError("metadata belongs to another project")
    if not isinstance(payload["project_path"], str) or os.path.normcase(payload["project_path"]) != os.path.normcase(str(expected_project)):
        raise ProcessSecurityError("metadata project path mismatch")
    _validate_int(payload["port"], "port", 1, 65535)
    if payload["port"] != expected_port:
        raise ProcessSecurityError("metadata port mismatch")
    _validate_int(payload["guardian_pid"], "guardian PID", 1, 0xFFFFFFFF)
    _validate_int(payload["guardian_creation_time"], "guardian creation identity", 1, 0x7FFFFFFFFFFFFFFF)
    _validate_int(payload["root_pid"], "root PID", 1, 0xFFFFFFFF)
    if payload["listener_pid"] is not None:
        _validate_int(payload["listener_pid"], "listener PID", 1, 0xFFFFFFFF)
    if payload["control_host"] != CONTROL_HOST:
        raise ProcessSecurityError("invalid control host")
    _validate_int(payload["control_port"], "control port", 1, 65535)
    if not isinstance(payload["control_token"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", payload["control_token"]):
        raise ProcessSecurityError("invalid control token")
    if not isinstance(payload["state"], str) or payload["state"] not in {"starting", "ready", "failed", "stopping"}:
        raise ProcessSecurityError("invalid process state")
    _validate_int(payload["started_at_unix_ns"], "start time", 1, 0x7FFFFFFFFFFFFFFF)
    if payload["failure_code"] is not None and (
        not isinstance(payload["failure_code"], str)
        or not re.fullmatch(r"[A-Z0-9_]{1,64}", payload["failure_code"])
    ):
        raise ProcessSecurityError("invalid failure code")
    return dict(payload)


def read_metadata(path: Path, key: bytes, *, expected_project: Path, expected_port: int) -> dict[str, Any]:
    try:
        _require_regular_single_link(path)
        with path.open("rb") as handle:
            raw_bytes = handle.read(MAX_CONTROL_MESSAGE + 1)
        if len(raw_bytes) > MAX_CONTROL_MESSAGE:
            raise ProcessSecurityError("process metadata is too large")
        raw = raw_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProcessSecurityError("process metadata is unavailable") from exc
    return validate_metadata(_loads_strict(raw), key, expected_project=expected_project, expected_port=expected_port)


def write_metadata(path: Path, payload: Mapping[str, Any], key: bytes) -> None:
    envelope = sign_metadata(payload, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".rad-process-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9
    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    CREATE_NO_WINDOW = 0x08000000
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_TERMINATE = 0x0001

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE


def _win_error(operation: str) -> ProcessSecurityError:
    return ProcessSecurityError(f"{operation} failed with Windows error {ctypes.get_last_error()}")


def process_creation_identity(pid: int) -> int | None:
    if os.name != "nt":
        raise ProcessSecurityError("Windows process identity is unavailable on this platform")
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            return None
        if exit_time.dwHighDateTime or exit_time.dwLowDateTime:
            return None  # a retained handle may keep an exited process object alive
        return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    finally:
        kernel32.CloseHandle(handle)


def process_identity_matches(pid: int, expected_creation_time: int) -> bool:
    actual = process_creation_identity(pid)
    return actual is not None and hmac.compare_digest(str(actual), str(expected_creation_time))


class WindowsJob:
    def __init__(self) -> None:
        if os.name != "nt":
            raise ProcessSecurityError("Windows Job Objects are required")
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise _win_error("CreateJobObjectW")
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            self.handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self.close()
            raise _win_error("SetInformationJobObject")

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def terminate(self, exit_code: int = 1) -> None:
        if not self.handle or not kernel32.TerminateJobObject(self.handle, exit_code):
            raise _win_error("TerminateJobObject")

    def contains_pid(self, pid: int) -> bool:
        process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            return False
        try:
            result = wintypes.BOOL()
            if not kernel32.IsProcessInJob(process, self.handle, ctypes.byref(result)):
                return False
            return bool(result.value)
        finally:
            kernel32.CloseHandle(process)

    def __enter__(self) -> "WindowsJob":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class _RunLease:
    """One live guardian per project/port, across concurrent launch clients."""
    def __init__(self, project: Path, port: int):
        name = "Local\\RAD-Process-" + project_identifier(project) + "-" + str(port)
        ctypes.set_last_error(0)
        self.handle = kernel32.CreateMutexW(None, False, name)
        error = ctypes.get_last_error()
        if not self.handle:
            raise _win_error("CreateMutexW")
        if error == 183:  # ERROR_ALREADY_EXISTS; never take over an existing run.
            kernel32.CloseHandle(self.handle)
            self.handle = None
            raise ProcessSecurityError("another guardian already owns this project/port run slot")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        kernel32.CloseHandle(self.handle)
        self.handle = None


def _windows_environment_block(environment: Mapping[str, str]) -> ctypes.Array[Any]:
    entries = [f"{key}={value}" for key, value in sorted(environment.items(), key=lambda item: item[0].casefold())]
    return ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")


def _safe_child_environment(extra: Sequence[str]) -> dict[str, str]:
    allowed = ("SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec", "PATHEXT")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    if os.name != "nt":
        raise ProcessSecurityError("Windows process environment is required")
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ProcessSecurityError("trusted Windows directory is unavailable")
    system_root = buffer.value
    environment["SystemRoot"] = system_root
    environment["WINDIR"] = system_root
    environment["ComSpec"] = str(Path(system_root) / "System32" / "cmd.exe")
    environment["PATH"] = str(Path(system_root) / "System32")
    for entry in extra:
        if "=" not in entry:
            raise ProcessSecurityError("environment entries must use NAME=VALUE")
        name, value = entry.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            raise ProcessSecurityError("invalid environment variable name")
        if "\0" in value or name.casefold() in {"systemroot", "windir", "comspec"}:
            raise ProcessSecurityError("cannot override the trusted command processor")
        environment[name] = value
    return environment


def create_process_in_job(command: str, working_directory: Path, job: WindowsJob, environment: Mapping[str, str]) -> tuple[int, int]:
    system_root = environment.get("SystemRoot", r"C:\Windows")
    command_processor = (Path(system_root) / "System32" / "cmd.exe").resolve(strict=True)
    # The /c payload is shell source, explicitly authorized as arbitrary code.
    # list2cmdline escapes quotes for the C runtime, NOT cmd.exe's parser.
    if not command or "\0" in command or len(command) > 24000:
        raise ProcessSecurityError("invalid command payload")
    command_line = '"' + str(command_processor) + '" /d /s /c "' + command + '"'
    mutable_command = ctypes.create_unicode_buffer(command_line)
    env_block = _windows_environment_block(environment)
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    process_info = PROCESS_INFORMATION()
    created = kernel32.CreateProcessW(
        str(command_processor),
        mutable_command,
        None,
        None,
        False,
        CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        env_block,
        str(working_directory),
        ctypes.byref(startup),
        ctypes.byref(process_info),
    )
    if not created:
        raise _win_error("CreateProcessW")
    try:
        if not kernel32.AssignProcessToJobObject(job.handle, process_info.hProcess):
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("AssignProcessToJobObject")
        creation = process_creation_identity(process_info.dwProcessId)
        if creation is None:
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise ProcessSecurityError("could not establish the created process identity")
        if kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("ResumeThread")
        return int(process_info.dwProcessId), creation
    finally:
        kernel32.CloseHandle(process_info.hThread)
        kernel32.CloseHandle(process_info.hProcess)


def listening_pids(port: int) -> list[int]:
    """Return IPv4/IPv6 owners; observations never grant termination authority."""
    if os.name != "nt":
        raise ProcessSecurityError("Windows TCP ownership is unavailable")
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    get_table = iphlpapi.GetExtendedTcpTable
    get_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    get_table.restype = wintypes.DWORD
    TCP_TABLE_OWNER_PID_LISTENER = 3
    ERROR_INSUFFICIENT_BUFFER = 122
    owners: list[int] = []
    for family, words, port_index, pid_index in ((2, 6, 2, 5), (23, 14, 5, 13)):
        # TCP tables can grow between the sizing and read calls. Bound retries.
        for _ in range(3):
            size = wintypes.DWORD(0)
            result = get_table(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            if result not in (0, ERROR_INSUFFICIENT_BUFFER) or not 4 <= size.value <= 16 * 1024 * 1024:
                raise ProcessSecurityError("GetExtendedTcpTable sizing failed")
            buffer = ctypes.create_string_buffer(size.value)
            result = get_table(buffer, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            if result == ERROR_INSUFFICIENT_BUFFER:
                continue
            if result != 0:
                raise ProcessSecurityError(f"GetExtendedTcpTable failed with error {result}")
            break
        else:
            raise ProcessSecurityError("TCP table changed repeatedly")
        count = ctypes.c_uint32.from_buffer(buffer, 0).value
        row_size = words * ctypes.sizeof(ctypes.c_uint32)
        if 4 + count * row_size > len(buffer):
            raise ProcessSecurityError("invalid TCP table size")
        for index in range(count):
            row = (ctypes.c_uint32 * words).from_buffer(buffer, 4 + index * row_size)
            if socket.ntohs(int(row[port_index]) & 0xFFFF) == port:
                owners.append(int(row[pid_index]))
    return sorted(set(owners))


def _validate_ready_url(value: str, port: int) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ProcessSecurityError("ready URL must be an unauthenticated HTTP(S) loopback URL")
    host = parsed.hostname
    if host is None:
        raise ProcessSecurityError("ready URL has no host")
    if host.casefold() != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ProcessSecurityError("ready URL must use loopback")
        except ValueError as exc:
            raise ProcessSecurityError("ready URL host must be a loopback address") from exc
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if actual_port != port:
        raise ProcessSecurityError("ready URL port must match the managed listener port")
    return value


class _NoReadinessRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _url_ready(url: str) -> bool:
    if not url:
        return True
    try:
        with build_opener(ProxyHandler({}), _NoReadinessRedirect()).open(url, timeout=2) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def _signed_response(body: Mapping[str, Any], token: str) -> bytes:
    body_dict = dict(body)
    mac = hmac.new(token.encode("ascii"), _canonical_json(body_dict), hashlib.sha256).hexdigest()
    return _canonical_json({"body": body_dict, "mac": mac}) + b"\n"


def _verify_response(response: Any, token: str, run_id: str, operation: str) -> dict[str, Any]:
    if not isinstance(response, dict) or set(response) != {"body", "mac"}:
        raise ProcessSecurityError("invalid guardian response")
    body = response["body"]
    mac = response["mac"]
    if not isinstance(body, dict) or not isinstance(mac, str):
        raise ProcessSecurityError("invalid guardian response")
    expected = hmac.new(token.encode("ascii"), _canonical_json(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ProcessSecurityError("guardian response authentication failed")
    if body.get("run_id") != run_id or body.get("operation") != operation or body.get("ok") is not True:
        raise ProcessSecurityError("guardian response identity mismatch")
    return body


def _receive_json(connection: socket.socket) -> Any:
    chunks = bytearray()
    while len(chunks) <= MAX_CONTROL_MESSAGE:
        part = connection.recv(min(4096, MAX_CONTROL_MESSAGE + 1 - len(chunks)))
        if not part:
            break
        chunks.extend(part)
        if b"\n" in part:
            break
    if len(chunks) > MAX_CONTROL_MESSAGE:
        raise ProcessSecurityError("control message is too large")
    raw_line = bytes(chunks).split(b"\n", 1)[0]
    try:
        text = raw_line.decode("utf-8")
    except UnicodeDecodeError as error:
        # Malformed unauthenticated data must never crash the guardian or
        # tear down its Job Object; fail the request before authentication.
        raise ProcessSecurityError("control message is not valid UTF-8") from error
    return _loads_strict(text)


def _control_request(payload: Mapping[str, Any], operation: str, timeout: float = 5.0) -> dict[str, Any]:
    request = {
        "operation": operation,
        "run_id": payload["run_id"],
        "project_id": payload["project_id"],
        "port": payload["port"],
        "token": payload["control_token"],
    }
    try:
        with socket.create_connection((payload["control_host"], payload["control_port"]), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(_canonical_json(request) + b"\n")
            response = _receive_json(connection)
    except (OSError, TimeoutError) as exc:
        raise ProcessSecurityError("authenticated guardian is unreachable") from exc
    return _verify_response(response, payload["control_token"], payload["run_id"], operation)


def stop_run(*, project: Path, port: int, state_directory: Path, key_file: Path, timeout: float = 5.0) -> dict[str, Any]:
    state, key_path = validate_trusted_state_paths(project, state_directory, key_file)
    key = load_key(key_path)
    path = metadata_path(state, project_identifier(project), port)
    payload = read_metadata(path, key, expected_project=project, expected_port=port)
    if payload["state"] not in {"starting", "ready"}:
        raise ProcessSecurityError(f"run is not stoppable from state {payload['state']}")
    if not process_identity_matches(payload["guardian_pid"], payload["guardian_creation_time"]):
        raise ProcessSecurityError("guardian process identity is stale or has been reused; refusing termination")
    response = _control_request(payload, "stop", timeout)
    if response.get("terminated_job") is not True:
        raise ProcessSecurityError("guardian did not confirm Job Object termination")
    # Keep the authenticated stopping tombstone. A late client must not unlink
    # a newer run's metadata at the same project/port. cleanup/start removes it
    # only after the guardian creation identity is no longer live.
    return response


def cleanup_state(*, project: Path, state_directory: Path, key_file: Path) -> tuple[int, int]:
    """Remove authenticated stale records. Never terminate a process."""
    state, key_path = validate_trusted_state_paths(project, state_directory, key_file)
    key = load_key(key_path)
    prefix = f"run-{project_identifier(project)[:24]}-"
    removed = 0
    retained = 0
    for path in state.glob(f"{prefix}*.json"):
        match = re.fullmatch(rf"{re.escape(prefix)}([0-9]{{1,5}})\.json", path.name)
        if not match:
            continue
        port = int(match.group(1))
        try:
            # A live guardian holds this lease. Holding it during stale cleanup
            # also prevents a new guardian replacing the record before unlink.
            with _RunLease(project, port):
                payload = read_metadata(path, key, expected_project=project, expected_port=port)
                if process_identity_matches(payload["guardian_pid"], payload["guardian_creation_time"]):
                    retained += 1
                    continue
                path.unlink()
                removed += 1
        except (ProcessSecurityError, OSError):
            retained += 1
    return removed, retained


def _guardian(
    *,
    command: str,
    port: int,
    project: Path,
    working_directory: Path,
    state_directory: Path,
    key_file: Path,
    ready_url: str,
    startup_timeout: float,
    environment_entries: Sequence[str],
) -> int:
    state, key_path = validate_trusted_state_paths(project, state_directory, key_file)
    key = load_key(key_path)
    path = metadata_path(state, project_identifier(project), port)
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    control.bind((CONTROL_HOST, 0))
    control.listen(4)
    control.settimeout(0.5)
    control_port = int(control.getsockname()[1])
    guardian_pid = os.getpid()
    guardian_creation = process_creation_identity(guardian_pid)
    if guardian_creation is None:
        raise ProcessSecurityError("guardian process identity is unavailable")
    run_id = secrets.token_hex(16)
    token = secrets.token_urlsafe(32)
    started_at = time.time_ns()
    ready_url = _validate_ready_url(ready_url, port)
    environment = _safe_child_environment(environment_entries)

    with _RunLease(project, port), WindowsJob() as job:
        root_pid, _root_creation = create_process_in_job(command, working_directory, job, environment)
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "run_id": run_id,
            "project_id": project_identifier(project),
            "project_path": str(project),
            "port": port,
            "guardian_pid": guardian_pid,
            "guardian_creation_time": guardian_creation,
            "root_pid": root_pid,
            "listener_pid": None,
            "control_host": CONTROL_HOST,
            "control_port": control_port,
            "control_token": token,
            "state": "starting",
            "started_at_unix_ns": started_at,
            "failure_code": None,
        }
        write_metadata(path, payload, key)
        deadline = time.monotonic() + startup_timeout
        owned_listener: int | None = None
        while time.monotonic() < deadline:
            owned_listener = None
            for listener_pid in listening_pids(port):
                if job.contains_pid(listener_pid):
                    owned_listener = listener_pid
                    break
            if owned_listener is not None and _url_ready(ready_url):
                break
            time.sleep(0.1)
        if owned_listener is None or not _url_ready(ready_url):
            payload["state"] = "failed"
            payload["failure_code"] = "STARTUP_NOT_OWNED_OR_NOT_READY"
            write_metadata(path, payload, key)
            job.terminate(2)
            return 2
        payload["listener_pid"] = owned_listener
        payload["state"] = "ready"
        write_metadata(path, payload, key)

        while True:
            try:
                connection, _address = control.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(3.0)
                try:
                    request = _receive_json(connection)
                    expected = {
                        "operation": request.get("operation") if isinstance(request, dict) else None,
                        "run_id": run_id,
                        "project_id": payload["project_id"],
                        "port": port,
                        "token": token,
                    }
                    if not isinstance(request, dict) or set(request) != set(expected) or any(request[k] != v for k, v in expected.items()):
                        raise ProcessSecurityError("control request identity mismatch")
                    operation = request["operation"]
                    if operation == "status":
                        body = {"ok": True, "operation": "status", "run_id": run_id, "state": "ready"}
                        connection.sendall(_signed_response(body, token))
                        continue
                    if operation != "stop":
                        raise ProcessSecurityError("unsupported control operation")
                    payload["state"] = "stopping"
                    write_metadata(path, payload, key)
                    job.terminate(0)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and any(job.contains_pid(pid) for pid in listening_pids(port)):
                        time.sleep(0.05)
                    port_free = not listening_pids(port)
                    body = {
                        "ok": True,
                        "operation": "stop",
                        "run_id": run_id,
                        "terminated_job": True,
                        "port_free": port_free,
                    }
                    try:
                        connection.sendall(_signed_response(body, token))
                    finally:
                        # A disconnected stop client must not leave a guardian
                        # alive indefinitely after its Job has been terminated.
                        return 0
                except (ProcessSecurityError, OSError, KeyError):
                    try:
                        connection.sendall(_signed_response({"ok": False, "operation": "error", "run_id": run_id}, token))
                    except OSError:
                        pass


def _spawn_guardian(arguments: argparse.Namespace) -> subprocess.Popen[bytes]:
    script = Path(__file__).resolve(strict=True)
    command = [
        sys.executable,
        "-I",
        "-B",
        str(script),
        "guardian",
        "--command",
        arguments.command,
        "--port",
        str(arguments.port),
        "--project",
        str(arguments.project),
        "--working-directory",
        str(arguments.working_directory),
        "--state-directory",
        str(arguments.state_directory),
        "--trust-key-file",
        str(arguments.trust_key_file),
        "--startup-timeout",
        str(arguments.startup_timeout),
    ]
    if arguments.ready_url:
        command.extend(["--ready-url", arguments.ready_url])
    for entry in arguments.environment:
        command.extend(["--environment", entry])
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
    guardian_environment = _safe_child_environment(())
    return subprocess.Popen(
        command,
        cwd=str(script.parent),
        env=guardian_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
    )


def start_run(arguments: argparse.Namespace) -> dict[str, Any]:
    if os.name != "nt":
        raise ProcessSecurityError("secure test-process ownership currently requires Windows")
    project = canonical_directory(arguments.project)
    working = canonical_directory(arguments.working_directory)
    if not _is_relative_to(Path(os.path.normcase(str(working))), Path(os.path.normcase(str(project)))):
        raise ProcessSecurityError("working directory must be within the project")
    state, key_path = validate_trusted_state_paths(project, Path(arguments.state_directory), Path(arguments.trust_key_file))
    key = load_or_create_key(key_path)
    path = metadata_path(state, project_identifier(project), arguments.port)
    if listening_pids(arguments.port):
        raise ProcessSecurityError(f"port {arguments.port} is already occupied")
    with _RunLease(project, arguments.port):
        if path.exists():
            try:
                existing = read_metadata(path, key, expected_project=project, expected_port=arguments.port)
            except ProcessSecurityError as exc:
                raise ProcessSecurityError("existing process metadata is invalid; refusing to overwrite it") from exc
            if process_identity_matches(existing["guardian_pid"], existing["guardian_creation_time"]):
                raise ProcessSecurityError("a managed run already exists for this project and port")
            path.unlink()
    arguments.project = project
    arguments.working_directory = working
    arguments.state_directory = state
    arguments.trust_key_file = key_path
    guardian = _spawn_guardian(arguments)
    deadline = time.monotonic() + arguments.startup_timeout + 5
    while time.monotonic() < deadline:
        if path.exists():
            try:
                payload = read_metadata(path, key, expected_project=project, expected_port=arguments.port)
            except ProcessSecurityError:
                time.sleep(0.05)
                continue
            if payload["state"] == "ready":
                if payload["guardian_pid"] != guardian.pid:
                    raise ProcessSecurityError("startup metadata belongs to a different guardian")
                if not process_identity_matches(payload["guardian_pid"], payload["guardian_creation_time"]):
                    raise ProcessSecurityError("guardian identity changed during startup")
                return payload
            if payload["state"] == "failed":
                raise ProcessSecurityError(f"test application startup failed: {payload['failure_code']}")
        if guardian.poll() is not None:
            raise ProcessSecurityError("guardian exited before establishing owned readiness")
        time.sleep(0.05)
    raise ProcessSecurityError("timed out waiting for the process guardian")


def _common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--trust-key-file", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RAD Windows test-process ownership helper")
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    _common_paths(start)
    start.add_argument("--command", required=True)
    start.add_argument("--port", type=int, required=True)
    start.add_argument("--working-directory", required=True)
    start.add_argument("--ready-url", default="")
    start.add_argument("--startup-timeout", type=float, default=45.0)
    start.add_argument("--environment", action="append", default=[])
    guardian = subparsers.add_parser("guardian", help=argparse.SUPPRESS)
    _common_paths(guardian)
    guardian.add_argument("--command", required=True)
    guardian.add_argument("--port", type=int, required=True)
    guardian.add_argument("--working-directory", required=True)
    guardian.add_argument("--ready-url", default="")
    guardian.add_argument("--startup-timeout", type=float, default=45.0)
    guardian.add_argument("--environment", action="append", default=[])
    stop = subparsers.add_parser("stop")
    _common_paths(stop)
    stop.add_argument("--port", type=int, required=True)
    stop.add_argument("--timeout", type=float, default=5.0)
    cleanup = subparsers.add_parser("cleanup")
    _common_paths(cleanup)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "start":
            if not 1 <= arguments.port <= 65535 or not 0.1 <= arguments.startup_timeout <= 300:
                raise ProcessSecurityError("invalid port or startup timeout")
            payload = start_run(arguments)
            print(json.dumps({"run_id": payload["run_id"], "root_pid": payload["root_pid"], "listener_pid": payload["listener_pid"], "port": payload["port"]}))
            return 0
        if arguments.action == "guardian":
            return _guardian(
                command=arguments.command,
                port=arguments.port,
                project=canonical_directory(arguments.project),
                working_directory=canonical_directory(arguments.working_directory),
                state_directory=Path(arguments.state_directory),
                key_file=Path(arguments.trust_key_file),
                ready_url=arguments.ready_url,
                startup_timeout=arguments.startup_timeout,
                environment_entries=arguments.environment,
            )
        project = canonical_directory(arguments.project)
        if arguments.action == "stop":
            if not 1 <= arguments.port <= 65535:
                raise ProcessSecurityError("invalid port")
            response = stop_run(
                project=project,
                port=arguments.port,
                state_directory=Path(arguments.state_directory),
                key_file=Path(arguments.trust_key_file),
                timeout=arguments.timeout,
            )
            print(json.dumps(response, sort_keys=True))
            return 0 if response.get("port_free") else 2
        removed, retained = cleanup_state(
            project=project,
            state_directory=Path(arguments.state_directory),
            key_file=Path(arguments.trust_key_file),
        )
        print(json.dumps({"removed": removed, "retained": retained}, sort_keys=True))
        return 0 if retained == 0 else 2
    except (ProcessSecurityError, OSError, ValueError) as exc:
        print(f"RAD process security error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
