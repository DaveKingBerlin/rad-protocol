"""Opt-in native Codex sandbox probe for the RAD security launcher.

This utility makes no API/model call. It runs fixed local commands under the
Codex built-in ``:read-only`` permission profile and emits JSON to stdout. Pass the
absolute, release-pinned Codex executable selected by the trusted launcher.
Running from inside an existing Windows restricted-token sandbox may fail at
the platform's nested-sandbox boundary; that is reported as an unverified
probe, never converted into a pass.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import socket
import threading


def sanitized_environment(temp_directory: Path) -> dict[str, str]:
    # Probe only the OS-known command processor, not inherited COMSPEC/PATH.
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise RuntimeError("Cannot resolve Windows directory")
    windows = Path(buffer.value)
    environment = {"SystemRoot": str(windows), "WINDIR": str(windows),
                   "ComSpec": str(windows / "System32/cmd.exe"),
                   "PATH": str(windows / "System32"),
                   "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
    # The native sandbox launcher needs the normal Windows profile locations.
    # They identify directories only; credential-bearing variables are not
    # copied. This probe does not claim to isolate Codex's own auth lookup.
    for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"):
        if name in os.environ:
            environment[name] = os.environ[name]
    environment["TEMP"] = str(temp_directory)
    environment["TMP"] = str(temp_directory)
    return environment


def run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", required=True, type=Path)
    args = parser.parse_args()

    if not args.codex.is_absolute():
        parser.error("--codex must be an absolute path")
    codex = args.codex.resolve(strict=True)
    if codex.name.lower() not in {"codex", "codex.exe"}:
        parser.error("--codex must identify an absolute Codex executable")

    external_parent = Path(__file__).resolve().parents[2].parent
    if not external_parent.is_dir():
        external_parent = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="rad-security-sentinel-",
                                      dir=str(external_parent)) as directory:
        sentinel_root = Path(directory).resolve()
        # Codex's Windows helper refuses to place its own aliases beneath the
        # OS temporary directory. Keep this isolated runtime home outside the
        # target and temp roots, then remove exactly that directory afterwards.
        project = sentinel_root / "project"
        external = sentinel_root / "external"
        project.mkdir()
        external.mkdir()
        readable = project / "readable.txt"
        readable.write_text("RAD-CODEX-READ-SENTINEL\n", encoding="utf-8")
        project_write = project / "project-write.sentinel"
        external_write = external / "host-write.sentinel"
        external_read = external / "host-read.sentinel"
        external_read.write_text("RAD-HOST-READ-SENTINEL", encoding="utf-8")
        (project / "project-write.cmd").write_text(
            "@echo off\r\necho x>project-write.sentinel\r\n", encoding="ascii"
        )
        (project / "host-write.cmd").write_text(
            '@echo off\r\ncopy /y readable.txt "{}" >nul\r\n'.format(external_write),
            encoding="ascii",
        )
        environment = sanitized_environment(sentinel_root)
        command_shell = Path(environment["ComSpec"]).resolve(strict=True)
        version = run([str(codex), "--version"], cwd=sentinel_root, environment=environment)
        common = [
            str(codex),
            "sandbox",
            "-P",
            ":read-only",
            "-C",
            str(project),
        ]
        read_probe = run(
            common + [str(command_shell), "/d", "/c", "type", "readable.txt"],
            cwd=sentinel_root,
            environment=environment,
        )
        project_probe = run(
            common + [str(command_shell), "/d", "/c", "project-write.cmd"],
            cwd=sentinel_root,
            environment=environment,
        )
        host_probe = run(
            common + [str(command_shell), "/d", "/c", "host-write.cmd"],
            cwd=sentinel_root,
            environment=environment,
        )
        host_read_probe = run(common + [str(command_shell), "/d", "/c", "type", str(external_read)],
                              cwd=sentinel_root, environment=environment)

        accepted_connections: list[bool] = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(4)
            port = server.getsockname()[1]

            def receive_once() -> None:
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    return
                with connection:
                    accepted_connections.append(True)

            receiver = threading.Thread(target=receive_once, daemon=True)
            receiver.start()
            network_probe = run(
                common
                + [
                    str(command_shell),
                    "/d",
                    "/c",
                    str(command_shell.parent / "curl.exe"),
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    "2",
                    "--max-time",
                    "5",
                    f"http://127.0.0.1:{port}/",
                ],
                cwd=sentinel_root,
                environment=environment,
            )
            receiver.join(timeout=5)

        legitimate_read = read_probe.returncode == 0 and "RAD-CODEX-READ-SENTINEL" in read_probe.stdout

        def denial_result(probe, effect_observed):
            if effect_observed:
                return "FAILED"
            # A failed process start does not prove that the attempted operation
            # ran and hit a boundary. Require a working positive control too.
            diagnostic = probe.stdout + probe.stderr
            if not legitimate_read or "windows sandbox failed:" in diagnostic:
                return "UNVERIFIED"
            return "BLOCKED" if probe.returncode != 0 else "UNVERIFIED"

        read_diagnostic = (read_probe.stderr or read_probe.stdout).replace(
            str(sentinel_root), "<sentinel>"
        )[-400:]
        result = {
            "codex": str(codex),
            "version": (version.stdout or version.stderr).strip(),
            "sandbox_available": legitimate_read,
            "readable_project_data": legitimate_read,
            "read_probe_returncode": read_probe.returncode,
            "read_probe_diagnostic": read_diagnostic,
            "probe_returncodes": {"project_write": project_probe.returncode, "host_write": host_probe.returncode,
                                  "host_read": host_read_probe.returncode, "network": network_probe.returncode},
            "network_mock_connections": len(accepted_connections),
            "network_probe_diagnostic": (network_probe.stderr or network_probe.stdout).replace(str(sentinel_root), "<sentinel>")[-400:],
            "project_write": denial_result(project_probe, project_write.exists()),
            "host_write": denial_result(host_probe, external_write.exists()),
            "host_read": denial_result(host_read_probe, "RAD-HOST-READ-SENTINEL" in host_read_probe.stdout),
            "loopback_network": denial_result(network_probe, bool(accepted_connections)),
            "environment_policy": "explicit allowlist; no credential variables copied",
        }
        result["passed"] = bool(
            legitimate_read and all(result[name] == "BLOCKED" for name in
                                    ("project_write", "host_write", "host_read", "loopback_network"))
        )
        print(json.dumps(result, sort_keys=True))
        return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
