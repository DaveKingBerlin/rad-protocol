"""Release-pinned RAD installation and target control-plane verification."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .policy import (
    FileClass,
    SecurityPolicyError,
    canonicalize_existing_directory,
    classify_path,
    is_control_plane,
    path_identity,
    validate_relative_path,
)
from .workspace import read_project_bytes


BASELINE_FILENAME = ".rad-security-baseline.json"
BASELINE_SCHEMA = "rad-security-baseline/v1"
POLICY_VERSION = 1
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_FILES = 20000
_EXCLUDED_PARTS = frozenset({".git", ".rad-local", ".pytest_cache", "__pycache__", "node_modules"})


class BaselineError(ValueError):
    """Raised for malformed baselines or unsafe release trees."""


@dataclass(frozen=True)
class FileRecord:
    path: str
    file_class: FileClass
    size: int
    sha256: str


@dataclass(frozen=True)
class TrustedBaseline:
    release_id: str
    release_sha256: str
    files: Tuple[FileRecord, ...]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    issues: Tuple[str, ...]


def _sha256_file(path: Path) -> Tuple[int, str]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise BaselineError("release and control-plane entries must be regular files: %s" % path)
    if getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise BaselineError("reparse-point files are not allowed: %s" % path)
    if before.st_size > MAX_FILE_BYTES:
        raise BaselineError("file exceeds security size limit: %s" % path)

    digest = hashlib.sha256()
    size = 0
    data = read_project_bytes(path.parent, path.name, MAX_FILE_BYTES)
    size = len(data)
    digest.update(data)
    after = path.lstat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise BaselineError("file changed during verification: %s" % path)
    return size, digest.hexdigest()


def iter_release_files(root_value: Union[str, os.PathLike[str]]) -> Iterable[Tuple[str, Path]]:
    root = canonicalize_existing_directory(root_value)
    def fail_walk(error):
        raise BaselineError("cannot enumerate the complete tree") from error
    entries = 0
    for current_text, directories, filenames in os.walk(root, topdown=True, followlinks=False, onerror=fail_walk):
        current = Path(current_text)
        entries += len(directories) + len(filenames)
        if entries > MAX_RELEASE_FILES or len(current.relative_to(root).parts) > 64:
            raise BaselineError("tree enumeration limit exceeded")
        kept_directories = []
        for name in sorted(directories):
            # Exclusions are installation artifacts only at the release root.
            # Skipping a matching name under .rad/, security/, or another
            # protected directory would let an attacker hide new authority.
            if current == root and name in _EXCLUDED_PARTS:
                continue
            child = current / name
            child_info = child.lstat()
            if child.is_symlink() or (
                getattr(child_info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise BaselineError("links and reparse-point directories are not allowed: %s" % child)
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(filenames):
            if current == root and name == BASELINE_FILENAME:
                continue
            path = current / name
            relative = validate_relative_path(path.relative_to(root).as_posix())
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise BaselineError("links and reparse-point files are not allowed: %s" % path)
            yield relative, path


def snapshot_release(root_value: Union[str, os.PathLike[str]]) -> Tuple[Tuple[FileRecord, ...], str]:
    records: List[FileRecord] = []
    identities = set()
    total = 0
    release_digest = hashlib.sha256()
    for relative, path in iter_release_files(root_value):
        identity = path_identity(relative)
        if identity in identities:
            raise BaselineError("case or Unicode-colliding release path: %s" % relative)
        identities.add(identity)
        size, file_digest = _sha256_file(path)
        total += size
        if total > MAX_RELEASE_BYTES:
            raise BaselineError("release exceeds security size limit")
        file_class = classify_path(relative)
        record = FileRecord(relative, file_class, size, file_digest)
        records.append(record)
        release_digest.update(relative.encode("utf-8"))
        release_digest.update(b"\x00")
        release_digest.update(str(size).encode("ascii"))
        release_digest.update(b"\x00")
        release_digest.update(bytes.fromhex(file_digest))
        release_digest.update(b"\x00")
    records.sort(key=lambda item: item.path.encode("utf-8"))
    # Recompute in sorted order so filesystem enumeration order cannot matter.
    release_digest = hashlib.sha256()
    for record in records:
        release_digest.update(record.path.encode("utf-8"))
        release_digest.update(b"\x00")
        release_digest.update(str(record.size).encode("ascii"))
        release_digest.update(b"\x00")
        release_digest.update(bytes.fromhex(record.sha256))
        release_digest.update(b"\x00")
    return tuple(records), release_digest.hexdigest()


def calculate_release_digest(root_value: Union[str, os.PathLike[str]]) -> str:
    return snapshot_release(root_value)[1]


def build_baseline(
    root_value: Union[str, os.PathLike[str]], release_id: str, release_sha256: str
) -> TrustedBaseline:
    if not isinstance(release_id, str) or not release_id or len(release_id) > 128:
        raise BaselineError("release_id must be a non-empty string of at most 128 characters")
    _validate_sha256(release_sha256, "release_sha256")
    records, actual_digest = snapshot_release(root_value)
    if actual_digest != release_sha256:
        raise BaselineError("release tree does not match the externally supplied digest")
    protected = tuple(
        record
        for record in records
        if record.file_class in (FileClass.CONTROL_PLANE, FileClass.GENERATED_CONTROL_OUTPUT)
    )
    return TrustedBaseline(release_id, release_sha256, protected)


def baseline_to_bytes(baseline: TrustedBaseline) -> bytes:
    document = {
        "schema": BASELINE_SCHEMA,
        "policy_version": POLICY_VERSION,
        "release_id": baseline.release_id,
        "release_sha256": baseline.release_sha256,
        "files": [
            {
                "path": item.path,
                "class": item.file_class.value,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in baseline.files
        ],
    }
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def _validate_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise BaselineError("%s must be a lowercase SHA-256 value" % field)
    if any(character not in "0123456789abcdef" for character in value):
        raise BaselineError("%s must be a lowercase SHA-256 value" % field)
    return value


def parse_baseline(data: bytes) -> TrustedBaseline:
    if len(data) > MAX_MANIFEST_BYTES:
        raise BaselineError("baseline manifest exceeds size limit")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BaselineError("baseline manifest is not strict UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise BaselineError("baseline manifest root must be an object")
    required = {"schema", "policy_version", "release_id", "release_sha256", "files"}
    if set(document) != required:
        raise BaselineError("baseline manifest has missing or unknown fields")
    if document["schema"] != BASELINE_SCHEMA or type(document["policy_version"]) is not int or document["policy_version"] != POLICY_VERSION:
        raise BaselineError("unsupported baseline schema or policy version")
    release_id = document["release_id"]
    if not isinstance(release_id, str) or not release_id or len(release_id) > 128:
        raise BaselineError("invalid release_id")
    release_sha256 = _validate_sha256(document["release_sha256"], "release_sha256")
    raw_files = document["files"]
    if not isinstance(raw_files, list):
        raise BaselineError("files must be an array")

    records: List[FileRecord] = []
    identities = set()
    previous_path = None
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"path", "class", "size", "sha256"}:
            raise BaselineError("file record has missing or unknown fields")
        relative = validate_relative_path(raw["path"])
        identity = path_identity(relative)
        if identity in identities:
            raise BaselineError("duplicate or case-colliding baseline path")
        identities.add(identity)
        if previous_path is not None and relative.encode("utf-8") <= previous_path.encode("utf-8"):
            raise BaselineError("baseline file records must be strictly sorted")
        previous_path = relative
        try:
            file_class = FileClass(raw["class"])
        except (TypeError, ValueError) as error:
            raise BaselineError("invalid file class") from error
        if file_class not in (FileClass.CONTROL_PLANE, FileClass.GENERATED_CONTROL_OUTPUT):
            raise BaselineError("baseline may contain only protected file classes")
        if classify_path(relative) != file_class:
            raise BaselineError("baseline file class disagrees with installed policy")
        size = raw["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_FILE_BYTES:
            raise BaselineError("invalid file size")
        sha256 = _validate_sha256(raw["sha256"], "file sha256")
        records.append(FileRecord(relative, file_class, size, sha256))
    return TrustedBaseline(release_id, release_sha256, tuple(records))


def load_baseline(path_value: Union[str, os.PathLike[str]]) -> TrustedBaseline:
    path = Path(path_value)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise BaselineError("baseline must be a regular non-link file")
    if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise BaselineError("baseline must not be a reparse point")
    return parse_baseline(read_project_bytes(path.parent, path.name, MAX_MANIFEST_BYTES))


def _protected_snapshot(root_value: Union[str, os.PathLike[str]]) -> Mapping[str, FileRecord]:
    result: Dict[str, FileRecord] = {}
    identities = set()
    for relative, path in iter_release_files(root_value):
        if not is_control_plane(relative):
            continue
        identity = path_identity(relative)
        if identity in identities:
            raise BaselineError("duplicate protected path")
        identities.add(identity)
        size, sha256 = _sha256_file(path)
        result[relative] = FileRecord(relative, classify_path(relative), size, sha256)
    return result


def verify_target(
    target_root: Union[str, os.PathLike[str]], baseline: TrustedBaseline
) -> VerificationResult:
    expected = {item.path: item for item in baseline.files}
    try:
        actual = _protected_snapshot(target_root)
    except (BaselineError, SecurityPolicyError, OSError) as error:
        return VerificationResult(False, ("unsafe target tree: %s" % error,))

    issues: List[str] = []
    for path in sorted(set(expected) - set(actual)):
        issues.append("missing protected file: %s" % path)
    for path in sorted(set(actual) - set(expected)):
        issues.append("unexpected protected file: %s" % path)
    for path in sorted(set(expected) & set(actual)):
        wanted = expected[path]
        found = actual[path]
        if wanted.file_class != found.file_class:
            issues.append("protected file class changed: %s" % path)
        if wanted.size != found.size or wanted.sha256 != found.sha256:
            issues.append("protected file content changed: %s" % path)
    return VerificationResult(not issues, tuple(issues))


def load_verified_installation(
    install_root: Union[str, os.PathLike[str]],
    expected_release_sha256: str,
    expected_release_id: Optional[str] = None,
) -> TrustedBaseline:
    """Load a baseline only after independently verifying its installation.

    The manifest itself is excluded from the release digest to avoid a circular
    hash.  It is therefore recomputed from the pinned installed payload and
    compared byte-for-byte with the stored records before it becomes authority.
    """
    _validate_sha256(expected_release_sha256, "expected_release_sha256")
    root = canonicalize_existing_directory(install_root)
    actual = calculate_release_digest(root)
    if actual != expected_release_sha256:
        raise BaselineError("installed release digest does not match external pin")
    baseline = load_baseline(root / BASELINE_FILENAME)
    if baseline.release_sha256 != expected_release_sha256:
        raise BaselineError("baseline release digest does not match external pin")
    if expected_release_id is not None and baseline.release_id != expected_release_id:
        raise BaselineError("installed release identifier does not match external pin")
    recomputed = build_baseline(root, baseline.release_id, expected_release_sha256)
    if baseline != recomputed:
        raise BaselineError("stored baseline does not match the pinned installed payload")
    return baseline


def verify_installation(
    install_root: Union[str, os.PathLike[str]],
    expected_release_sha256: str,
    expected_release_id: Optional[str] = None,
) -> VerificationResult:
    """Return a fail-closed diagnostic result for installation verification."""

    try:
        load_verified_installation(install_root, expected_release_sha256, expected_release_id)
    except (BaselineError, SecurityPolicyError, OSError) as error:
        return VerificationResult(False, (str(error),))
    return VerificationResult(True, ())


def verify_target_against_installation(
    install_root: Union[str, os.PathLike[str]],
    target_root: Union[str, os.PathLike[str]],
    expected_release_sha256: str,
    expected_release_id: Optional[str] = None,
) -> VerificationResult:
    """Atomically establish installed authority and verify a target against it."""

    try:
        baseline = load_verified_installation(
            install_root, expected_release_sha256, expected_release_id
        )
    except (BaselineError, SecurityPolicyError, OSError) as error:
        return VerificationResult(False, ("untrusted RAD installation: %s" % error,))
    return verify_target(target_root, baseline)
