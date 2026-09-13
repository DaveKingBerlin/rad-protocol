"""RAD control-plane path classification and product-mode authorization.

This module is intended to be imported from a release-pinned RAD installation,
not from the untrusted project being inspected.  Classification is deliberately
independent of repository instructions and writable evidence.
"""

from __future__ import annotations

import os
import stat
import unicodedata
from enum import Enum
from pathlib import Path
from typing import Iterable, Union


PathLike = Union[str, os.PathLike[str]]


class SecurityPolicyError(ValueError):
    """Raised when a path cannot be interpreted safely."""


class FileClass(str, Enum):
    CONTROL_PLANE = "CONTROL_PLANE"
    GENERATED_CONTROL_OUTPUT = "GENERATED_CONTROL_OUTPUT"
    PRODUCT_WORKSPACE = "PRODUCT_WORKSPACE"
    EVIDENCE_REPORTING = "EVIDENCE_REPORTING"


class OperationMode(str, Enum):
    PRODUCT = "PRODUCT"
    MAINTENANCE = "MAINTENANCE"


class Role(str, Enum):
    ORCHESTRATOR = "orchestrator"
    FRONTEND_DEV = "frontend-dev"
    BACKEND_DEV = "backend-dev"
    QA = "qa"
    ADVERSARY = "adversary"


_GENERATED_PREFIXES = (".codex", ".opencode", ".claude", ".cursor", ".agents")
_CONTROL_PREFIXES = (".rad", ".github", ".git", "security", "scripts", "tests/security")
_CONTROL_EXACT = frozenset(
    {
        ".gitignore",
        ".gitattributes",
        ".gitmodules",
        ".mcp.json",
        ".rad-security-baseline.json",
        "agents.md",
        "decisions.md",
        "opencode.json",
        "opencode.jsonc",
        "requirements.md",
        "security.md",
        "tools/generate_adapters.py",
        "opencode.json", "opencode.jsonc", ".mcp.json", ".cursorrules",
        "docs/trusted_baseline.md", "docs/secure_mode.md", "docs/process_ownership.md",
        "docs/runtime_support.md",
    }
)
_EVIDENCE_EXACT = frozenset(
    {
        "adversarial_review.md",
        "benchmarks.md",
        "defects.md",
        "naming_audit.md",
        "poc_report.md",
    }
)
_EVIDENCE_PREFIXES = ("screenshots/evidence", "screenshots/generated", "e2e/artifacts")
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", "clock$"}
    | {"com%d" % value for value in range(1, 10)}
    | {"lpt%d" % value for value in range(1, 10)}
)


def validate_relative_path(value: PathLike) -> str:
    """Return a canonical POSIX relative path or reject ambiguous input.

    Windows alternate data streams, device names, traversal, empty segments,
    normalization ambiguity, and drive/UNC paths are rejected on every host so
    a manifest has the same meaning across supported platforms.
    """

    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise SecurityPolicyError("path must be a text or path-like value") from error
    if not isinstance(raw, str) or not raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise SecurityPolicyError("path must be a non-empty text value")
    if any(c in raw for c in '~<>"|?*'):
        raise SecurityPolicyError("ambiguous/device/wildcard/short-name path characters are not allowed")
    if unicodedata.normalize("NFC", raw) != raw:
        raise SecurityPolicyError("path must use NFC Unicode normalization")
    normalized = raw.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise SecurityPolicyError("absolute and UNC paths are not allowed")
    if ":" in normalized:
        raise SecurityPolicyError("drive-qualified paths and alternate data streams are not allowed")

    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SecurityPolicyError("empty, current, and parent path segments are not allowed")
    for part in parts:
        if part[-1:] in (" ", "."):
            raise SecurityPolicyError("trailing spaces and dots are not allowed")
        stem = part.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED:
            raise SecurityPolicyError("Windows device path segments are not allowed")
    return "/".join(parts)


def path_identity(value: PathLike) -> str:
    """Return the cross-platform collision identity of a relative path."""

    return unicodedata.normalize("NFC", validate_relative_path(value)).casefold()


def _has_prefix(identity: str, prefixes: Iterable[str]) -> bool:
    return any(identity == prefix or identity.startswith(prefix + "/") for prefix in prefixes)


def classify_path(value: PathLike) -> FileClass:
    """Classify a project-relative path under the RAD security policy."""

    relative = validate_relative_path(value)
    identity = relative.casefold()

    if identity == "claude.md" or _has_prefix(identity, _GENERATED_PREFIXES):
        return FileClass.GENERATED_CONTROL_OUTPUT
    if identity in _CONTROL_EXACT or _has_prefix(identity, _CONTROL_PREFIXES):
        return FileClass.CONTROL_PLANE

    # Instruction files apply below the repository root in several runtimes.
    # Treat every occurrence as control material, not merely the root copy.
    leaf = identity.rsplit("/", 1)[-1]
    if leaf in ("agents.md", "claude.md", "opencode.json", "opencode.jsonc", ".mcp.json", ".cursorrules"):
        return FileClass.CONTROL_PLANE
    if any(part in _GENERATED_PREFIXES or part in (".rad", ".git", ".vscode", ".devcontainer")
           for part in identity.split("/")):
        return FileClass.CONTROL_PLANE

    if identity in _EVIDENCE_EXACT or _has_prefix(identity, _EVIDENCE_PREFIXES):
        return FileClass.EVIDENCE_REPORTING
    return FileClass.PRODUCT_WORKSPACE


def is_control_plane(value: PathLike) -> bool:
    return classify_path(value) in (FileClass.CONTROL_PLANE, FileClass.GENERATED_CONTROL_OUTPUT)


def product_write_allowed(role: Role, value: PathLike) -> bool:
    """Apply role ownership in product mode.

    Maintenance authorization is intentionally absent from this function.  A
    trusted launcher must enter maintenance mode before exposing a different
    write policy; project text, reports, or model output cannot change this
    result.
    """

    file_class = classify_path(value)
    if file_class in (FileClass.CONTROL_PLANE, FileClass.GENERATED_CONTROL_OUTPUT):
        return False
    if file_class == FileClass.PRODUCT_WORKSPACE:
        identity = validate_relative_path(value).casefold()
        if _has_prefix(identity, ("e2e",)):
            return role == Role.QA
        return role in (Role.FRONTEND_DEV, Role.BACKEND_DEV)

    identity = validate_relative_path(value).casefold()
    if role == Role.QA:
        return identity in ("defects.md", "naming_audit.md") or _has_prefix(
            identity, ("e2e", "screenshots/evidence", "screenshots/generated")
        )
    if role == Role.ADVERSARY:
        return identity == "adversarial_review.md" or _has_prefix(
            identity, ("screenshots/evidence", "screenshots/generated")
        )
    return role == Role.ORCHESTRATOR


def _is_reparse_or_link(path: Path) -> bool:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _reject_unsafe_absolute_components(path: Path) -> None:
    anchor = Path(path.anchor)
    current = anchor
    for part in path.parts[1:]:
        if unicodedata.normalize("NFC", part) != part:
            raise SecurityPolicyError("absolute path components must use NFC Unicode normalization")
        stem = part.split(".", 1)[0].casefold()
        if part[-1:] in (" ", ".") or ":" in part or stem in _WINDOWS_RESERVED:
            raise SecurityPolicyError("ambiguous absolute path component")
        current = current / part
        if not current.exists():
            break
        if _is_reparse_or_link(current):
            raise SecurityPolicyError("symbolic links, junctions, and reparse points are not allowed")


def canonicalize_existing_directory(value: PathLike) -> Path:
    """Canonicalize an absolute existing directory without traversing links."""

    path = Path(value)
    if not path.is_absolute():
        raise SecurityPolicyError("trusted paths must be absolute")
    _reject_unsafe_absolute_components(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SecurityPolicyError("directory does not exist or cannot be resolved") from error
    if not resolved.is_dir():
        raise SecurityPolicyError("path is not a directory")
    _reject_unsafe_absolute_components(resolved)
    return resolved


def canonicalize_new_directory(value: PathLike) -> Path:
    """Validate an absolute, not-yet-existing installation directory."""

    path = Path(value)
    if not path.is_absolute():
        raise SecurityPolicyError("trusted paths must be absolute")
    if path.exists() or path.is_symlink():
        raise SecurityPolicyError("installation destination must not already exist")
    parent = canonicalize_existing_directory(path.parent)
    candidate = parent / path.name
    _reject_unsafe_absolute_components(candidate)
    return candidate


def ensure_disjoint_paths(first: PathLike, second: PathLike) -> None:
    """Reject equal or nested trusted/project paths."""

    left = os.path.normcase(os.path.abspath(os.fspath(first)))
    right = os.path.normcase(os.path.abspath(os.fspath(second)))
    try:
        common = os.path.commonpath((left, right))
    except ValueError as error:
        # Different Windows volumes are necessarily disjoint.
        if os.name == "nt":
            return
        raise SecurityPolicyError("paths cannot be compared") from error
    if common == left or common == right:
        raise SecurityPolicyError("trusted installation and project/source paths must be disjoint")
