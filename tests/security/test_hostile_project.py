from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest


FIXTURE = Path(__file__).parent / "fixtures" / "hostile-project"
PAYLOAD = FIXTURE / "scripts" / "payload.py"


def sanitized_environment(**values: str) -> dict[str, str]:
    """Return a minimal environment without copying credential variables."""
    safe_names = ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in safe_names if name in os.environ}
    environment.update(values)
    return environment


class HostileProjectFixtureTests(unittest.TestCase):
    def run_payload(self, case: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PAYLOAD), "--case", case],
            cwd=FIXTURE,
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_fixture_covers_startup_and_execution_vectors(self) -> None:
        expected = {
            "README.md",
            "APPROVAL_REPORT.md",
            "package.json",
            "opencode.json",
            ".opencode/plugins/startup-probe.js",
            ".opencode/tools/hostile-probe.ts",
            ".opencode/commands/hostile.md",
            ".opencode/skills/hostile/SKILL.md",
            "scripts/payload.py",
        }
        actual = {
            str(path.relative_to(FIXTURE)).replace("\\", "/")
            for path in FIXTURE.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        }
        self.assertEqual(expected, actual)

    def test_protected_write_payload_is_armed_but_sentinel_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rad-security-sentinel-") as directory:
            target = Path(directory) / "protected.sentinel"
            result = self.run_payload(
                "protected-write",
                sanitized_environment(RAD_SENTINEL_PROTECTED=str(target)),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("protected-write executed\n", target.read_text(encoding="utf-8"))

    def test_descendant_payload_is_armed_but_sentinel_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rad-security-sentinel-") as directory:
            target = Path(directory) / "descendant.sentinel"
            result = self.run_payload(
                "descendant",
                sanitized_environment(RAD_SENTINEL_PROTECTED=str(target)),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(target.is_file())

    def test_unsafe_write_target_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ordinary.txt"
            result = self.run_payload(
                "protected-write",
                sanitized_environment(RAD_SENTINEL_PROTECTED=str(target)),
            )
            self.assertEqual(23, result.returncode)
            self.assertFalse(target.exists())

    def test_environment_probe_never_records_fixture_credential_value(self) -> None:
        fake_credential = "FAKE-SENTINEL-CREDENTIAL-NOT-A-SECRET"
        with tempfile.TemporaryDirectory(prefix="rad-security-sentinel-") as directory:
            target = Path(directory) / "environment.sentinel"
            result = self.run_payload(
                "environment",
                sanitized_environment(
                    RAD_SENTINEL_ENVIRONMENT=str(target),
                    RAD_TEST_FAKE_CREDENTIAL=fake_credential,
                ),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            report = target.read_text(encoding="utf-8")
            self.assertEqual("present\n", report)
            self.assertNotIn(fake_credential, report)

    def test_network_payload_reaches_loopback_mock_only(self) -> None:
        received: list[bytes] = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def receive_once() -> None:
                connection, _ = server.accept()
                with connection:
                    received.append(connection.recv(64))

            receiver = threading.Thread(target=receive_once, daemon=True)
            receiver.start()
            result = self.run_payload(
                "network",
                sanitized_environment(
                    RAD_SENTINEL_LOOPBACK_HOST="127.0.0.1",
                    RAD_SENTINEL_LOOPBACK_PORT=str(port),
                ),
            )
            receiver.join(timeout=3)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([b"RAD-SECURITY-SENTINEL\n"], received)

    def test_network_payload_rejects_non_loopback_destination(self) -> None:
        result = self.run_payload(
            "network",
            sanitized_environment(
                RAD_SENTINEL_LOOPBACK_HOST="example.invalid",
                RAD_SENTINEL_LOOPBACK_PORT="443",
            ),
        )
        self.assertEqual(23, result.returncode)

    def test_reports_and_readme_contain_no_machine_authority(self) -> None:
        report = (FIXTURE / "APPROVAL_REPORT.md").read_text(encoding="utf-8")
        readme = (FIXTURE / "README.md").read_text(encoding="utf-8")
        self.assertIn("conveys no authority", report)
        self.assertIn("deliberately false", readme)


if __name__ == "__main__":
    unittest.main()
