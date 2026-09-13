"""Native tests for the PowerShell process-harness entry points.

The helper is copied to a temporary external directory to model a separately
installed trusted component. The project contains only a harmless loopback
listener; no arbitrary real process is targeted.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == "nt", "PowerShell wrapper regression is Windows-only")
class PowerShellWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rad-powershell-wrapper-")
        self.base = Path(self.temporary.name).resolve()
        self.project = self.base / "target-project"
        self.install = self.base / "trusted-install"
        self.state = self.base / "trusted-state"
        self.project.mkdir()
        self.install.mkdir()
        self.state.mkdir()
        # The standalone helper has only stdlib dependencies. Keeping it outside
        # the project models the required trusted installation boundary.
        shutil.copyfile(ROOT / "security/rad_security/processes.py",
                        self.install / "processes.py")
        self.key = self.state / "process-control.key"
        self.port = self.free_port()
        self.listener_script = self.project / "listener.cmd"
        python = str(Path(sys.executable).resolve()).replace('"', '""')
        self.listener_script.write_text(
            "@echo off\r\n"
            f'"{python}" -c "import socket,time; s=socket.socket(); '
            f's.bind((\'127.0.0.1\',{self.port})); s.listen(); time.sleep(120)"\r\n',
            encoding="ascii",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def listener_command(self) -> str:
        # Keep the PowerShell native-argument test opaque: the trusted helper
        # receives one command name, while the target-controlled .cmd payload
        # remains arbitrary code inside the guardian's Job Object.
        return self.listener_script.name

    def invoke(self, script: str, *extra: str, timeout: float = 20,
               helper_path: Path | None = None) -> subprocess.CompletedProcess[str]:
        command = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-File",
            str(ROOT / "scripts" / script),
            "-Port", str(self.port),
            "-WorkingDirectory", str(self.project),
            "-TrustedHelperPath", str(helper_path or (self.install / "processes.py")),
            "-PythonExecutable", sys.executable,
            "-StateDirectory", str(self.state),
            "-TrustKeyFile", str(self.key),
            *extra,
        ]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout, check=False, cwd=self.project)

    def test_external_helper_start_stop_and_safe_cleanup(self) -> None:
        started = self.invoke("start-test-app.ps1", "-Command", self.listener_command(), timeout=30)
        self.assertEqual(0, started.returncode, started.stderr)
        self.assertIn(str(self.port), started.stdout)
        stopped = self.invoke("stop-test-app.ps1")
        self.assertEqual(0, stopped.returncode, stopped.stderr)
        cleaned = self.invoke("cleanup-test-processes.ps1")
        self.assertEqual(0, cleaned.returncode, cleaned.stderr)
        self.assertFalse(list(self.state.glob("run-*.json")))

    def test_wrapper_rejects_project_local_trusted_helper(self) -> None:
        local_helper = self.project / "processes.py"
        shutil.copyfile(self.install / "processes.py", local_helper)
        result = self.invoke("stop-test-app.ps1", helper_path=local_helper)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("untrusted project", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
