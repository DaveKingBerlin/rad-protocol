"""Harmless payloads for RAD hostile-project security regression tests.

Every write requires an explicit environment path containing
``rad-security-sentinel-`` and ending in ``.sentinel``. Network activity is
restricted to a caller-provided loopback endpoint. Missing or unsafe targets
fail closed.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys


TARGETS = {
    "protected-write": "RAD_SENTINEL_PROTECTED",
    "host-write": "RAD_SENTINEL_HOST",
    "formatter": "RAD_SENTINEL_FORMATTER",
    "lsp": "RAD_SENTINEL_LSP",
    "mcp": "RAD_SENTINEL_MCP",
    "custom-tool": "RAD_SENTINEL_CUSTOM_TOOL",
    "environment": "RAD_SENTINEL_ENVIRONMENT",
}


def sentinel_path(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        raise ValueError(f"missing {variable}")
    target = Path(value)
    if not target.is_absolute():
        raise ValueError("sentinel path must be absolute")
    target = target.resolve(strict=False)
    if "rad-security-sentinel-" not in str(target).lower():
        raise ValueError("target is not inside a security sentinel fixture")
    if target.suffix != ".sentinel":
        raise ValueError("sentinel target must use the .sentinel suffix")
    if not target.parent.is_dir():
        raise ValueError("sentinel parent must already exist")
    return target


def write_probe(case: str) -> None:
    target = sentinel_path(TARGETS[case])
    if case == "environment":
        # Record presence only. Never copy even the fixture credential value.
        content = "present\n" if "RAD_TEST_FAKE_CREDENTIAL" in os.environ else "absent\n"
    else:
        content = f"{case} executed\n"
    target.write_text(content, encoding="utf-8")


def network_probe() -> None:
    host = os.environ.get("RAD_SENTINEL_LOOPBACK_HOST", "")
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("network fixture permits loopback only")
    port = int(os.environ.get("RAD_SENTINEL_LOOPBACK_PORT", "0"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid loopback sentinel port")
    with socket.create_connection((host, port), timeout=2) as connection:
        connection.sendall(b"RAD-SECURITY-SENTINEL\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        required=True,
        choices=sorted([*TARGETS, "descendant", "network"]),
    )
    args = parser.parse_args()
    if args.case == "descendant":
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--case", "protected-write"],
            check=False,
            env=os.environ.copy(),
        )
        return completed.returncode
    if args.case == "network":
        network_probe()
        return 0
    write_probe(args.case)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"probe blocked: {error}", file=sys.stderr)
        raise SystemExit(23)
