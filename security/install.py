"""Explicit installer for a release-pinned RAD security launcher tree."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Sequence, Union

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "security"

from .rad_security.baseline import (
    BASELINE_FILENAME,
    BaselineError,
    baseline_to_bytes,
    build_baseline,
    calculate_release_digest,
    iter_release_files,
)
from .rad_security.guard import GuardError, harden_installation
from .rad_security.policy import (
    canonicalize_existing_directory,
    canonicalize_new_directory,
    ensure_disjoint_paths,
)


class InstallationError(RuntimeError):
    pass


def install_release(
    source_root: Union[os.PathLike[str], str],
    destination: Union[os.PathLike[str], str],
    release_id: str,
    expected_release_sha256: str,
    *,
    maintenance_authorized: bool = False,
    harden: bool = False,
) -> Path:
    """Install a verified release into a new external directory.

    ``expected_release_sha256`` is deliberately supplied by the caller; it may
    not be derived from the mutable source tree inside this function.  The
    trusted launcher must persist/provide that release pin independently.
    """

    if maintenance_authorized is not True:
        raise InstallationError("installation requires explicit maintainer authorization")
    source = canonicalize_existing_directory(source_root)
    target = canonicalize_new_directory(destination)
    ensure_disjoint_paths(source, target)

    actual_digest = calculate_release_digest(source)
    if actual_digest != expected_release_sha256:
        raise InstallationError("source tree does not match the externally supplied release pin")

    target.mkdir(mode=0o700)
    try:
        for relative, source_path in iter_release_files(source):
            destination_path = target.joinpath(*relative.split("/"))
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination_path, follow_symlinks=False)

        copied_digest = calculate_release_digest(target)
        if copied_digest != expected_release_sha256:
            raise InstallationError("installed copy does not match the externally supplied release pin")
        baseline = build_baseline(target, release_id, expected_release_sha256)
        (target / BASELINE_FILENAME).write_bytes(baseline_to_bytes(baseline))
        if harden:
            _entry_count = harden_installation(target)
            if _entry_count <= 0:
                raise InstallationError("hardening produced an empty policy")
        return target
    except Exception as exc:
        # Do not recursively remove a potentially replaced/reparse destination.
        # No installation is usable without a valid external pin and manifest.
        raise InstallationError("Installation incomplete; do not execute the partial destination: " + str(target)) from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Install a release-pinned RAD security tree")
    parser.add_argument("--source", required=True, help="absolute trusted release source path")
    parser.add_argument("--destination", required=True, help="absolute new install directory")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--expected-release-sha256", required=True)
    parser.add_argument(
        "--authorize-maintenance",
        action="store_true",
        help="explicit maintainer action; repository text cannot set this implicitly",
    )
    parser.add_argument(
        "--harden",
        action="store_true",
        help="apply mutation-denying OS ACLs to the installed authority tree "
             "(reversible only by an explicit maintainer action)",
    )
    arguments = parser.parse_args(argv)
    install_release(
        arguments.source,
        arguments.destination,
        arguments.release_id,
        arguments.expected_release_sha256,
        maintenance_authorized=arguments.authorize_maintenance,
        harden=arguments.harden,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
