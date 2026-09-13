"""Structured product-file operations; never executes project commands.

This broker is a building block, not a sandbox for an independently launched
coding runtime. Backends must route edits here OR supply equivalent OS isolation.
Windows directory handles disallow write/delete sharing during each operation,
preventing reparse-point insertion or ancestor replacement while paths are used.
"""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import stat
import tempfile

from .policy import (Role, SecurityPolicyError, canonicalize_existing_directory,
                     product_write_allowed, validate_relative_path)


MAX_DATA_BYTES = 2 * 1024 * 1024


if os.name == "nt":
    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.HANDLE]
    _kernel.CreateFileW.restype = wintypes.HANDLE
    _kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel.CloseHandle.restype = wintypes.BOOL

    class _FileInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    _kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInfo)]
    _kernel.GetFileInformationByHandle.restype = wintypes.BOOL


def _open_windows(path, directory=False, write=False):
    # Metadata-only FILE_READ_ATTRIBUTES does not establish data-sharing locks.
    # GENERIC_READ is necessary to enforce the omitted WRITE/DELETE sharing.
    access = 0x80000000 | (0x40000000 if write else 0)
    flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE / BACKUP
    handle = _kernel.CreateFileW(str(path), access, 0 if write else 1, None,
                                 4 if write else 3, flags, None)  # OPEN_ALWAYS / OPEN_EXISTING
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Cannot open locked non-reparse path", str(path))
    info = _FileInfo()
    if not _kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        _kernel.CloseHandle(handle)
        raise SecurityPolicyError("Cannot verify file handle identity")
    if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
        _kernel.CloseHandle(handle)
        raise SecurityPolicyError("Reparse or unexpected file type refused")
    if not directory and info.links != 1:
        _kernel.CloseHandle(handle)
        raise SecurityPolicyError("Hardlinked file refused")
    return handle


@contextmanager
def _locked_parents(root, relative):
    if os.name != "nt":
        # Do not silently replace handle-relative semantics with resolve+open.
        raise SecurityPolicyError("Structured workspace broker currently requires Windows")
    relative = validate_relative_path(relative)
    destination = Path(root).joinpath(*relative.split("/"))
    handles = []
    try:
        current = Path(destination.anchor)
        handles.append(_open_windows(current, directory=True))
        for part in destination.parts[1:-1]:
            current /= part
            handles.append(_open_windows(current, directory=True))
        yield destination
    finally:
        for handle in reversed(handles):
            _kernel.CloseHandle(handle)


def read_project_bytes(root, relative, max_bytes=MAX_DATA_BYTES):
    """No-follow, single-link, size-bounded read with locked ancestor handles."""
    if os.name != "nt":
        relative = validate_relative_path(relative)
        destination = Path(root).joinpath(*relative.split("/"))
        if not destination.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
            raise SecurityPolicyError("No safe handle-relative filesystem API")
        directory = os.open(destination.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in destination.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise SecurityPolicyError("Special or hardlinked file refused")
                data = source.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise SecurityPolicyError("File exceeds structured read size limit")
            return data
        finally:
            os.close(directory)
    with _locked_parents(root, relative) as path:
        handle = _open_windows(path)
        import msvcrt
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except Exception:
            _kernel.CloseHandle(handle)
            raise
        with os.fdopen(descriptor, "rb") as source:
            data = source.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise SecurityPolicyError("File exceeds structured read size limit")
        return data


class ProductWorkspace:
    """A fixed-role, data-only write capability with no maintenance override."""
    def __init__(self, root, role):
        self.root = canonicalize_existing_directory(root)
        self.role = Role(role)

    def read(self, relative):
        rel = validate_relative_path(relative)
        # This is not a secret scanner. Exclude common secret stores up front;
        # deployment still must exclude all sensitive project data as needed.
        for part in rel.casefold().split("/"):
            if part == ".git" or part == ".env" or part.startswith(".env."):
                raise SecurityPolicyError("Sensitive project data is not broker-readable")
        return read_project_bytes(self.root, rel)

    def write(self, relative, data):
        rel = validate_relative_path(relative)
        if not product_write_allowed(self.role, rel):
            raise SecurityPolicyError("Product role cannot modify protected/control or other-role files")
        if not isinstance(data, bytes) or len(data) > MAX_DATA_BYTES:
            raise SecurityPolicyError("Write must be bounded bytes")
        with _locked_parents(self.root, rel) as path:
            # OPEN_ALWAYS does not truncate. Validate the exclusive file handle
            # before writing; all I/O then uses that same verified object. No
            # rename-by-path operation or second check/open window is required.
            handle = _open_windows(path, write=True)
            import msvcrt
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except Exception:
                _kernel.CloseHandle(handle)
                raise
            with os.fdopen(fd, "r+b") as target:
                target.write(data)
                target.truncate()
                target.flush()
                os.fsync(target.fileno())
