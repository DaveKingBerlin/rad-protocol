from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import argparse


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from security.rad_security import processes  # noqa: E402


@unittest.skipUnless(os.name == "nt", "Windows Job Object regression suite")
class WindowsProcessOwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rad-process-security-")
        self.base = Path(self.temporary.name)
        self.project = self.base / "untrusted-project"
        self.state = self.base / "trusted-state"
        self.project.mkdir()
        self.state.mkdir()
        self.key_file = self.state / "process-control.key"
        self.key = processes.load_or_create_key(self.key_file)
        self.controlled_processes: list[subprocess.Popen[bytes]] = []
        self.active_ports: set[int] = set()

    def tearDown(self) -> None:
        for port in list(self.active_ports):
            try:
                processes.stop_run(
                    project=self.project.resolve(),
                    port=port,
                    state_directory=self.state,
                    key_file=self.key_file,
                    timeout=1,
                )
            except processes.ProcessSecurityError:
                pass
        for child in self.controlled_processes:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        self.temporary.cleanup()

    @staticmethod
    def free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    @staticmethod
    def listener_command(port: int, delay: float = 0) -> str:
        code = (
            "import socket,sys,time;"
            f"time.sleep({delay!r});"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.bind(('127.0.0.1',int(sys.argv[1])));s.listen();time.sleep(120)"
        )
        return subprocess.list2cmdline([sys.executable, "-c", code, str(port)])

    @staticmethod
    def sleeper_command(seconds: int = 120) -> str:
        return subprocess.list2cmdline([sys.executable, "-c", f"import time;time.sleep({seconds})"])

    def cli(self, action: str, *arguments: str, timeout: float = 15) -> subprocess.CompletedProcess[str]:
        helper = ROOT / "security" / "rad_security" / "processes.py"
        command = [
            sys.executable,
            str(helper),
            action,
            "--project",
            str(self.project),
            "--state-directory",
            str(self.state),
            "--trust-key-file",
            str(self.key_file),
            *arguments,
        ]
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)

    def start_owned(self, port: int, *, delay: float = 0, timeout: float = 5) -> dict[str, object]:
        result = self.cli(
            "start",
            "--command",
            self.listener_command(port, delay),
            "--port",
            str(port),
            "--working-directory",
            str(self.project),
            "--startup-timeout",
            str(timeout),
            timeout=timeout + 8,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.active_ports.add(port)
        return json.loads(result.stdout)

    def state_path(self, port: int) -> Path:
        return processes.metadata_path(self.state, processes.project_identifier(self.project.resolve()), port)

    def signed_payload(self, port: int, guardian_pid: int, creation: int) -> dict[str, object]:
        return {
            "schema": processes.SCHEMA,
            "run_id": secrets.token_hex(16),
            "project_id": processes.project_identifier(self.project.resolve()),
            "project_path": str(self.project.resolve()),
            "port": port,
            "guardian_pid": guardian_pid,
            "guardian_creation_time": creation,
            "root_pid": guardian_pid,
            "listener_pid": None,
            "control_host": processes.CONTROL_HOST,
            "control_port": self.free_port(),
            "control_token": secrets.token_urlsafe(32),
            "state": "ready",
            "started_at_unix_ns": time.time_ns(),
            "failure_code": None,
        }

    def controlled_sleeper(self) -> subprocess.Popen[bytes]:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(120)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.controlled_processes.append(child)
        return child

    def controlled_listener(self, port: int) -> subprocess.Popen[bytes]:
        child = subprocess.Popen(
            [sys.executable, "-c", (
                "import socket,sys,time;"
                "s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));"
                "s.listen();time.sleep(120)"
            ), str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.controlled_processes.append(child)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if child.pid in processes.listening_pids(port):
                return child
            if child.poll() is not None:
                self.fail("controlled listener exited unexpectedly")
            time.sleep(0.05)
        self.fail("controlled listener did not become ready")

    def test_owned_process_is_terminated_through_its_job(self) -> None:
        port = self.free_port()
        started = self.start_owned(port)
        root_pid = int(started["root_pid"])
        response = processes.stop_run(
            project=self.project.resolve(),
            port=port,
            state_directory=self.state,
            key_file=self.key_file,
        )
        self.active_ports.discard(port)
        self.assertTrue(response["terminated_job"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and processes.process_creation_identity(root_pid) is not None:
            time.sleep(0.05)
        self.assertIsNone(processes.process_creation_identity(root_pid))
        self.assertEqual(processes.listening_pids(port), [])

    def test_forged_pid_cannot_terminate_unrelated_sentinel(self) -> None:
        sentinel = self.controlled_sleeper()
        creation = processes.process_creation_identity(sentinel.pid)
        self.assertIsNotNone(creation)
        port = self.free_port()
        processes.write_metadata(self.state_path(port), self.signed_payload(port, sentinel.pid, int(creation)), self.key)
        with self.assertRaises(processes.ProcessSecurityError):
            processes.stop_run(
                project=self.project.resolve(), port=port, state_directory=self.state, key_file=self.key_file, timeout=0.2
            )
        self.assertIsNone(sentinel.poll())

    def test_stale_metadata_never_falls_back_to_pid_termination(self) -> None:
        sentinel = self.controlled_sleeper()
        port = self.free_port()
        payload = self.signed_payload(port, sentinel.pid, 1)
        processes.write_metadata(self.state_path(port), payload, self.key)
        with self.assertRaisesRegex(processes.ProcessSecurityError, "stale or has been reused"):
            processes.stop_run(
                project=self.project.resolve(), port=port, state_directory=self.state, key_file=self.key_file
            )
        self.assertIsNone(sentinel.poll())

    def test_pid_reuse_identity_mismatch_is_refused(self) -> None:
        sentinel = self.controlled_sleeper()
        actual = processes.process_creation_identity(sentinel.pid)
        self.assertIsNotNone(actual)
        port = self.free_port()
        processes.write_metadata(self.state_path(port), self.signed_payload(port, sentinel.pid, int(actual) + 1), self.key)
        with self.assertRaisesRegex(processes.ProcessSecurityError, "stale or has been reused"):
            processes.stop_run(
                project=self.project.resolve(), port=port, state_directory=self.state, key_file=self.key_file
            )
        self.assertIsNone(sentinel.poll())

    def test_unrelated_listener_winning_port_race_survives(self) -> None:
        port = self.free_port()
        helper = ROOT / "security" / "rad_security" / "processes.py"
        command = [
            sys.executable, str(helper), "start",
            "--project", str(self.project),
            "--state-directory", str(self.state),
            "--trust-key-file", str(self.key_file),
            "--command", self.sleeper_command(),
            "--port", str(port),
            "--working-directory", str(self.project),
            "--startup-timeout", "1.5",
        ]
        starter = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        state_path = self.state_path(port)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not state_path.exists():
            self.assertIsNone(starter.poll(), "starter exited before race fixture was established")
            time.sleep(0.05)
        listener = self.controlled_listener(port)
        stdout, stderr = starter.communicate(timeout=10)
        self.assertNotEqual(starter.returncode, 0, stdout + stderr)
        self.assertIsNone(listener.poll())
        self.assertIn(listener.pid, processes.listening_pids(port))

    def test_corrupt_duplicate_incomplete_and_invalid_metadata_fail_safely(self) -> None:
        sentinel = self.controlled_sleeper()
        port = self.free_port()
        cases = (
            "{not-json",
            '{"payload":{},"payload":{},"mac":"' + ("0" * 64) + '"}',
            json.dumps({"payload": {}, "mac": "0" * 64}),
            json.dumps({"payload": {"guardian_pid": sentinel.pid}, "mac": "0" * 64}),
        )
        for raw in cases:
            with self.subTest(raw=raw[:24]):
                self.state_path(port).write_text(raw, encoding="utf-8")
                with self.assertRaises(processes.ProcessSecurityError):
                    processes.stop_run(
                        project=self.project.resolve(), port=port, state_directory=self.state, key_file=self.key_file
                    )
                self.assertIsNone(sentinel.poll())

    def test_interrupted_start_client_can_be_cleaned_up_safely(self) -> None:
        port = self.free_port()
        helper = ROOT / "security" / "rad_security" / "processes.py"
        command = [
            sys.executable, str(helper), "start",
            "--project", str(self.project),
            "--state-directory", str(self.state),
            "--trust-key-file", str(self.key_file),
            "--command", self.listener_command(port, delay=1),
            "--port", str(port),
            "--working-directory", str(self.project),
            "--startup-timeout", "5",
        ]
        starter = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        state_path = self.state_path(port)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not state_path.exists():
            self.assertIsNone(starter.poll(), "starter exited before guardian state was written")
            time.sleep(0.05)
        starter.terminate()
        starter.wait(timeout=3)
        deadline = time.monotonic() + 7
        payload = None
        while time.monotonic() < deadline:
            try:
                payload = processes.read_metadata(
                    state_path, self.key, expected_project=self.project.resolve(), expected_port=port
                )
            except processes.ProcessSecurityError:
                time.sleep(0.05)
                continue
            if payload["state"] == "ready":
                break
            time.sleep(0.05)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["state"], "ready")
        self.active_ports.add(port)
        response = processes.stop_run(
            project=self.project.resolve(), port=port, state_directory=self.state, key_file=self.key_file
        )
        self.active_ports.discard(port)
        self.assertTrue(response["terminated_job"])

    def test_binary_trust_key_preserves_newline_bytes(self):
        key_path = self.state / "binary-test.key"
        with mock.patch.object(processes.secrets, "token_bytes", return_value=b"\n" * 32):
            self.assertEqual(b"\n" * 32, processes.load_or_create_key(key_path))
        self.assertEqual(32, key_path.stat().st_size)

    def test_active_cleanup_retains_state_without_killing_owned_job(self):
        port = self.free_port()
        self.start_owned(port)
        self.assertEqual((0, 1), processes.cleanup_state(project=self.project.resolve(),
            state_directory=self.state, key_file=self.key_file))
        self.assertTrue(self.state_path(port).exists())
        self.assertTrue(processes.listening_pids(port))

    def test_authorized_test_does_not_inherit_credential_environment(self):
        port = self.free_port()
        code = ("import os,pathlib,socket,time;"
                "pathlib.Path('environment.sentinel').write_text(str('RAD_FAKE_API_KEY' in os.environ));"
                "s=socket.socket();s.bind(('127.0.0.1',%d));s.listen();time.sleep(120)" % port)
        command = subprocess.list2cmdline([sys.executable, "-c", code])
        with mock.patch.dict(os.environ, {"RAD_FAKE_API_KEY": "NOT-A-REAL-CREDENTIAL"}):
            result = self.cli("start", "--command", command, "--port", str(port),
                              "--working-directory", str(self.project), "--startup-timeout", "5")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("False", (self.project / "environment.sentinel").read_text())
        self.active_ports.add(port)

    def test_malformed_utf8_control_message_fails_safely(self):
        """PH3/Phase-4 #12: unauthenticated malformed UTF-8 must be a safe
        request failure, never a guardian-crashing UnicodeDecodeError."""
        left, right = socket.socketpair()
        try:
            right.sendall(b"control request \xff\x81\xfe payload\n")
            with self.assertRaises(processes.ProcessSecurityError):
                processes._receive_json(left)
            left.settimeout(1)
            # The receiver remains usable for a subsequent well-formed frame.
            right.sendall(b"control request bytes\n")
            with self.assertRaises(processes.ProcessSecurityError):
                processes._receive_json(left)
        finally:
            left.close()
            right.close()

    def test_even_signed_unrelated_root_pid_does_not_change_job_ownership(self):
        sentinel = self.controlled_sleeper()
        port = self.free_port()
        self.start_owned(port)
        payload = processes.read_metadata(self.state_path(port), self.key,
                                          expected_project=self.project.resolve(), expected_port=port)
        payload["root_pid"] = sentinel.pid
        payload["listener_pid"] = sentinel.pid
        processes.write_metadata(self.state_path(port), payload, self.key)
        response = processes.stop_run(project=self.project.resolve(), port=port,
                                      state_directory=self.state, key_file=self.key_file)
        self.active_ports.discard(port)
        self.assertTrue(response["terminated_job"])
        self.assertIsNone(sentinel.poll())

    def test_signed_invalid_field_types_are_safe_errors(self):
        sentinel = self.controlled_sleeper()
        port = self.free_port()
        payload = self.signed_payload(port, sentinel.pid, int(processes.process_creation_identity(sentinel.pid)))
        for key, value in (("project_path", []), ("state", []), ("guardian_pid", True),
                           ("control_port", -1), ("run_id", "../other")):
            changed = dict(payload, **{key: value})
            processes.write_metadata(self.state_path(port), changed, self.key)
            with self.subTest(key=key), self.assertRaises(processes.ProcessSecurityError):
                processes.stop_run(project=self.project.resolve(), port=port,
                                   state_directory=self.state, key_file=self.key_file)
            self.assertIsNone(sentinel.poll())

    def test_detached_descendant_remains_job_owned(self):
        port = self.free_port()
        child_code = "import socket,time; s=socket.socket();s.bind(('127.0.0.1',%d));s.listen();time.sleep(120)" % port
        parent_code = ("import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child_code) +
                       "],creationflags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NO_WINDOW)")
        command = subprocess.list2cmdline([sys.executable, "-c", parent_code])
        result = self.cli("start", "--command", command, "--port", str(port),
                          "--working-directory", str(self.project), "--startup-timeout", "5")
        self.assertEqual(0, result.returncode, result.stderr)
        self.active_ports.add(port)
        response = processes.stop_run(project=self.project.resolve(), port=port,
                                      state_directory=self.state, key_file=self.key_file)
        self.active_ports.discard(port)
        self.assertTrue(response["terminated_job"])
        self.assertEqual([], processes.listening_pids(port))

    def test_guardian_interruption_closes_job_and_stale_cleanup_is_safe(self):
        port = self.free_port()
        arguments = argparse.Namespace(command=self.listener_command(port), port=port,
            project=self.project.resolve(), working_directory=self.project.resolve(),
            state_directory=self.state, trust_key_file=self.key_file,
            startup_timeout=5, ready_url="", environment=[])
        guardian = processes._spawn_guardian(arguments)
        self.controlled_processes.append(guardian)
        deadline = time.monotonic() + 7
        ready = False
        while time.monotonic() < deadline:
            if self.state_path(port).exists():
                payload = processes.read_metadata(self.state_path(port), self.key,
                    expected_project=self.project.resolve(), expected_port=port)
                if payload["state"] == "ready":
                    ready = True
                    break
            self.assertIsNone(guardian.poll())
            time.sleep(0.05)
        self.assertTrue(ready)
        guardian.terminate()  # Popen handle of this fixture's guardian, never metadata PID.
        guardian.wait(timeout=3)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and processes.listening_pids(port):
            time.sleep(0.05)
        self.assertEqual([], processes.listening_pids(port))
        removed, retained = processes.cleanup_state(project=self.project.resolve(),
            state_directory=self.state, key_file=self.key_file)
        self.assertEqual((1, 0), (removed, retained))


if __name__ == "__main__":
    unittest.main()
