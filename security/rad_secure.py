#!/usr/bin/env python3
"""Run with an absolute trusted Python path and -I from an installed release.

The Python interpreter, this bootstrap and its installed directory are the
external trust anchor. A self-hash is integrity checking, not authentication.
"""

import argparse
import json
from pathlib import Path
import sys

# -I excludes cwd, PYTHONPATH and user site-packages. Only this installed package
# directory is added; never the requested target or the caller's current folder.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rad_security.launcher import (NetworkPolicy, launch_trusted_project,
                                   matrix_as_dicts, prepare_secure_launch,
                                   verify_project)
from rad_security.guard import GuardError, lock_control_plane
from rad_security.policy import Role
from rad_security.workspace import ProductWorkspace, MAX_DATA_BYTES


def main(argv=None):
    parser = argparse.ArgumentParser(description="Installed RAD security bootstrap (fail closed)")
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("capabilities", help="Report release-owned capability status; does not launch")
    verify = sub.add_parser("verify", help="Check target against installed independent baseline")
    launch = sub.add_parser("launch", help="Secure by default; no implicit trusted-mode fallback")
    guard = sub.add_parser("guard", help="Lock/verify/unlock the repository control plane at the OS boundary")
    read = sub.add_parser("read", help="Structured bounded product data read (no subprocess)")
    write = sub.add_parser("write", help="Structured product edit; bounded bytes from stdin, no control edits")
    for command in (verify, launch, guard, read, write):
        command.add_argument("--project", type=Path, required=True)
        command.add_argument("--release-sha256", required=True,
                             help="Reviewed release pin obtained outside the target checkout")
    guard.add_argument("--action", choices=("lock", "verify", "unlock"), required=True)
    for command in (read, write):
        command.add_argument("--path", required=True, help="Unambiguous project-relative file path")
        command.add_argument("--role", choices=[role.value for role in Role], required=True)
    launch.add_argument("--runtime", choices=("codex", "codex-wsl", "opencode", "claude", "cursor"), required=True)
    launch.add_argument("--network", choices=[p.value for p in NetworkPolicy], default=NetworkPolicy.NONE.value)
    launch.add_argument("--mode", choices=("secure", "trusted-project"), default="secure")
    launch.add_argument("--acknowledge-trusted-project", action="store_true")
    launch.add_argument("--guard-control-plane", action="store_true",
                        help="Required for trusted-project launch: OS-lock the repository control plane for the session")
    launch.add_argument("--runtime-executable", type=Path)
    launch.add_argument("--runtime-sha256")
    launch.add_argument("--wsl-codex-sha256",
                        help="Independently pinned SHA-256 of the Codex binary "
                             "inside the certified WSL distribution (required for codex-wsl Secure Launch)")
    launch.add_argument("--wsl-command",
                        help="Operator-provided inner command run inside the sandbox (bash -c)")
    launch.add_argument("--wsl-env", action="append", default=[],
                        help="NAME=VALUE environment entry passed into the sandbox (repeatable)")
    args = parser.parse_args(argv)
    installation = Path(__file__).resolve().parents[1]
    try:
        if args.operation == "capabilities":
            print(json.dumps(matrix_as_dicts(), indent=2))
            return 0
        if args.operation == "verify":
            result = verify_project(installation, args.project, args.release_sha256)
            print(json.dumps({"baseline": "verified", "inventory": result}, indent=2))
            return 0
        if args.operation == "guard":
            verify_project(installation, args.project, args.release_sha256)
            if args.action == "lock":
                guarded = lock_control_plane(args.project)
                guarded.verify()
                print(json.dumps({
                    "control_plane": "locked",
                    "locker_pid": __import__("os").getpid(),
                }, indent=2))
                return 0
            if args.action == "verify":
                # Purely observational; never changes ACL state.
                from rad_security.guard import check_control_plane_locked
                if check_control_plane_locked(args.project):
                    print(json.dumps({"control_plane": "guard-effective"}, indent=2))
                    return 0
                print(json.dumps({"control_plane": "not-locked"}, indent=2), file=sys.stderr)
                return 2
            if args.action == "unlock":
                from rad_security.guard import unlock_control_plane
                count = unlock_control_plane(args.project)
                print(json.dumps({"control_plane": "unlocked", "entries": count}, indent=2))
                return 0
        if args.operation in ("read", "write"):
            verify_project(installation, args.project, args.release_sha256)
            workspace = ProductWorkspace(args.project, args.role)
            if args.operation == "read":
                sys.stdout.buffer.write(workspace.read(args.path))
            else:
                workspace.write(args.path, sys.stdin.buffer.read(MAX_DATA_BYTES + 1))
            return 0
        if args.mode == "secure":
            if args.acknowledge_trusted_project or args.runtime_executable or args.runtime_sha256:
                parser.error("Trusted-project options cannot authorize Secure Mode")
            if args.runtime == "codex-wsl":
                # PH3-007: the single public hostile-project secure launch path.
                from rad_security.wsl_backend import WslBackendError, launch_secure_run
                if not args.wsl_codex_sha256:
                    parser.error(
                        "--wsl-codex-sha256 is required for codex-wsl Secure Launch; "
                        "Secure Mode refuses startup without an independent binary pin")
                # Baseline verification precedes any staging/execution.
                verify_project(installation, args.project, args.release_sha256)
                environment = {}
                for entry in args.wsl_env:
                    if "=" not in entry or entry.count("=") != 1:
                        parser.error("--wsl-env must be NAME=VALUE")
                    name, value = entry.split("=", 1)
                    environment[name] = value
                inner = ["bash", "-c", args.wsl_command] if args.wsl_command else []
                result = launch_secure_run(
                    args.project,
                    codex_sha256=args.wsl_codex_sha256,
                    inner=inner,
                    environment=environment,
                )
                print(json.dumps({
                    "backend": "codex-wsl",
                    "status": "SUPPORTED",
                    "platform": "linux/wsl2",
                    "network": "disabled",
                    "ok": bool(result["ok"]),
                    "run_rc": result["run_rc"] if "run_rc" in result else None,
                    "stdout_tail": (result.get("stdout") or "")[-2000:],
                }, indent=2))
                return 0 if result["ok"] else 2
            admitted = prepare_secure_launch(installation, args.project, args.runtime,
                                             args.release_sha256, args.network)
            return 0
        if args.network != NetworkPolicy.TRUSTED.value:
            parser.error("Trusted-project launch requires --network 'UNRESTRICTED TRUSTED MODE'")
        if not args.runtime_executable or not args.runtime_sha256:
            parser.error("Trusted-project launch requires absolute executable and SHA-256 pin")
        if not args.guard_control_plane:
            parser.error("Trusted-project launch requires --guard-control-plane; "
                         "the repository control plane must be OS-locked before any runtime process starts")
        print("WARNING: TRUSTED-PROJECT ONLY. No hostile-repository sandbox guarantee.", file=sys.stderr)
        return launch_trusted_project(installation, args.project, args.runtime,
                                      args.release_sha256, args.runtime_executable,
                                      args.runtime_sha256, args.acknowledge_trusted_project,
                                      guard_control_plane=True)
    except (RuntimeError, ValueError, OSError) as exc:
        print("RAD REFUSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
