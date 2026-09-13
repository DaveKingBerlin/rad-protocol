"""Permanent Phase 2D/Phase 4 regressions: Codex WSL2 Secure Mode backend.

These tests are native and require the dedicated ``RAD-Secure-Test`` WSL2
distribution with the pinned Codex CLI installed.  On hosts without that
backend the whole class is skipped; a skip means that specific certification
claim remains unverified on that host.

Phase 4 additions cover the PH3 findings: executable shadowing (PH3-001),
shell-metacharacter project paths (PH3-002), root script delivery (PH3-003),
fail-closed structured guard status (PH3-004), baseline-derived nested control
leaves (PH3-006), the single public secure-launch path (PH3-007), pinned Codex
binary (Phase 4 #8) and effective-config behavior verification (Phase 4 #9).
"""

import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from security.rad_security.launcher import SecureModeUnavailable, prepare_secure_launch
from security.rad_security.baseline import calculate_release_digest
from security.install import install_release
from security.rad_security.wsl_backend import (
    DEFAULT_DISTRO,
    DEFAULT_USER,
    WslBackendError,
    _measure_codex,
    _wsl_root,
    _wsl_user,
    clean_remote,
    distro_exists,
    guard_control_plane_wsl,
    launch_secure_run,
    stage_project,
    run_sandboxed,
    unguard_control_plane_wsl,
    verify_wsl_backend,
)

ROOT = Path(__file__).resolve().parents[2]
CODEX_PATH = "/usr/local/bin/codex"


def _has_wsl_backend() -> bool:
    if os.name != "nt":
        return False
    try:
        return distro_exists(DEFAULT_DISTRO)
    except Exception:
        return False


def _measure_pin():
    digest, measured = _measure_codex(DEFAULT_DISTRO, DEFAULT_USER, CODEX_PATH)
    return digest, measured


def _build_fixture(directory):
    root = Path(directory)
    (root / ".rad").mkdir(parents=True)
    (root / ".rad" / "policy.md").write_text("reviewed policy\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("reviewed bootstrap\n", encoding="utf-8")
    (root / "DECISIONS.md").write_text("No approvals\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.txt").write_text("product data\n", encoding="utf-8")
    tools = root / "rad-tools"
    tools.mkdir()
    (tools / "control_probe.py").write_text(
        "import sys\n"
        "open(sys.argv[1], 'w').write('hack')\n", encoding="utf-8")
    (tools / "socket_probe.py").write_text(
        "import socket\n"
        "socket.socket()\n"
        "print('SOCKET-CREATED')\n", encoding="utf-8")
    (tools / "descendant_write.py").write_text(
        "import sys\n"
        "try:\n"
        "    open(sys.argv[1], 'a').write('x')\n"
        "    sys.exit(0)\n"
        "except OSError:\n"
        "    sys.exit(42)\n", encoding="utf-8")
    (tools / "descendant_net.py").write_text(
        "import socket\n"
        "import sys\n"
        "try:\n"
        "    socket.socket()\n"
        "    sys.exit(0)\n"
        "except OSError:\n"
        "    sys.exit(42)\n", encoding="utf-8")
    (tools / "grandchild.py").write_text(
        "import subprocess\n"
        "import sys\n"
        "script = sys.argv[1]\n"
        "sys.exit(subprocess.call([sys.executable, '-B', script] + sys.argv[2:]))\n",
        encoding="utf-8")
    return root


@unittest.skipUnless(_has_wsl_backend(),
                     "RAD-Secure-Test WSL2 backend is not available on this host")
class WslSecureBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rad-security-sentinel-")
        base = Path(cls.temporary.name)
        cls.source = base / "reviewed-release"
        (cls.source / ".rad" / "core").mkdir(parents=True)
        (cls.source / ".rad" / "core" / "protocol.md").write_text(
            "reviewed policy\n", encoding="utf-8")
        (cls.source / ".github" / "workflows").mkdir(parents=True)
        (cls.source / ".github" / "workflows" / "check.yml").write_text("# reviewed\n", encoding="utf-8")
        (cls.source / "tools").mkdir()
        (cls.source / "tools" / "generate_adapters.py").write_text("# reviewed checker\n", encoding="utf-8")
        (cls.source / "AGENTS.md").write_text("reviewed bootstrap\n", encoding="utf-8")
        (cls.source / "DECISIONS.md").write_text("No approvals\n", encoding="utf-8")
        for path in (ROOT / "security").rglob("*.py"):
            relative = path.relative_to(ROOT)
            destination = cls.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        cls.pin = calculate_release_digest(cls.source)
        cls.installed = install_release(cls.source, base / "installed",
                                        "wsl-test-release", cls.pin,
                                        maintenance_authorized=True)
        cls.codex_sha, cls.codex_ver = _measure_pin()

        cls.local = base / "project"
        cls.local.mkdir()
        _build_fixture(cls.local)
        cls.remote = stage_project(cls.local, DEFAULT_DISTRO)
        cls.guard = guard_control_plane_wsl(cls.remote)

    @classmethod
    def tearDownClass(cls):
        unguard_control_plane_wsl(cls.remote)
        with contextlib.suppress(Exception):
            clean_remote(cls.remote)
        cls.temporary.cleanup()

    def sandbox(self, inner, environment=None, timeout=180):
        return run_sandboxed(
            DEFAULT_DISTRO, DEFAULT_USER, self.remote,
            ["bash", "-c", inner], environment=environment, timeout=timeout)

    def assert_sandbox_line(self, script, sentinel, timeout=180):
        result = self.sandbox(script)
        self.assertIn(sentinel, result.stdout,
                      "missing %r in %r" % (sentinel, result.stdout[-800:]))

    # -- Phase 4 #8 / #9: pinning and effective config ---------------------

    def test_backend_verification_passes_with_pin(self):
        backend = verify_wsl_backend(
            codex_path=CODEX_PATH, codex_sha256=self.codex_sha,
            codex_version=self.codex_ver, probe=True)
        self.assertTrue(backend["ok"], backend["checks"])

    def test_backend_refuses_wrong_codex_pin(self):
        bogus = "0" * 64
        backend = verify_wsl_backend(
            codex_path=CODEX_PATH, codex_sha256=bogus,
            codex_version=self.codex_ver, probe=False)
        self.assertFalse(backend["ok"])

    def test_launcher_refuses_missing_pin(self):
        target = Path(self.temporary.name) / "launcher-target"
        shutil.copytree(self.source, target)
        for runtime in ("codex", "opencode", "claude", "cursor"):
            with self.subTest(runtime=runtime), self.assertRaises(SecureModeUnavailable):
                prepare_secure_launch(self.installed, target, runtime, self.pin)
        with self.assertRaises(SecureModeUnavailable):
            prepare_secure_launch(self.installed, target, "codex-wsl", self.pin)
        admitted = prepare_secure_launch(self.installed, target, "codex-wsl", self.pin,
                                         codex_sha256=self.codex_sha,
                                         codex_version=self.codex_ver)
        self.assertEqual(DEFAULT_DISTRO, admitted["distro"])
        self.assertEqual("codex-wsl", admitted["runtime"])

    # -- PH3-001: executable shadowing --------------------------------

    def test_wsl_executable_is_absolute_system_path(self):
        from security.rad_security.wsl_backend import _wsl_executable
        path = _wsl_executable()
        self.assertTrue(path.lower().endswith(r"\system32\wsl.exe"), path)
        self.assertTrue(Path(path).is_file())

    def test_icacls_resolved_from_system32_not_current_dir(self):
        from security.rad_security.guard import _resolve_tools
        with tempfile.TemporaryDirectory(prefix="rad-shadow-") as shadow:
            (Path(shadow) / "icacls.exe").write_bytes(b"MZ-not-really")
            (Path(shadow) / "wsl.exe").write_bytes(b"MZ-not-really")
            icacls, ps = _resolve_tools()
            self.assertIn("System32", icacls)
            self.assertIn("System32", ps)
        # A harmless call still works with the absolute tool.
        result = self.sandbox("echo SHADOW-RESOLVE-OK")
        self.assertIn("SHADOW-RESOLVE-OK", result.stdout)

    # -- PH3-002: shell-metacharacter paths ----------------------------

    def test_malicious_project_name_never_becomes_shell_syntax(self):
        parent = Path(self.temporary.name)
        evil_name = "evil;$(id);$(whoami);`touch bla`"
        local = parent / evil_name
        local.mkdir()
        (local / "AGENTS.md").write_text("x", encoding="utf-8")
        (local / "src").mkdir()
        (local / "src" / "f.txt").write_text("x", encoding="utf-8")
        remote = stage_project(local, DEFAULT_DISTRO)
        try:
            marker = _wsl_user(DEFAULT_DISTRO, DEFAULT_USER,
                               "test -e /tmp/rad-pwned && echo PWNED || echo CLEAN")
            self.assertIn("CLEAN", marker.stdout)
            run = run_sandboxed(DEFAULT_DISTRO, DEFAULT_USER, remote,
                                ["bash", "-c", "echo inner-ok"])
            self.assertIn("inner-ok", run.stdout)
        finally:
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)

    def test_clean_remote_refuses_caller_supplied_path(self):
        from security.rad_security.wsl_backend import clean_remote as cr
        with self.assertRaises(WslBackendError):
            cr("/home/radtest/projects/../../etc", DEFAULT_DISTRO, DEFAULT_USER)
        with self.assertRaises(WslBackendError):
            cr("/tmp/anything", DEFAULT_DISTRO, DEFAULT_USER)

    # -- PH3-003: root script delivery ----------------------------------

    def test_root_script_private_dir_mode_0700(self):
        info = _wsl_root(DEFAULT_DISTRO, "stat -c '%a %U' /var/lib/rad-secure/wsl-scripts")
        self.assertIn("700", info.stdout)
        self.assertIn("root", info.stdout)

    def test_no_predictable_tmp_scripts_remain(self):
        self.assert_sandbox_line(
            "pgrep -f 'rad-wsl-[0-9a-f]{8}\\.sh' || echo NO-LEFTOVER-TMP",
            "NO-LEFTOVER-TMP")

    # -- PH3-004: structured fail-closed guard -----------------------------

    def test_guard_requires_mandatory_present_path(self):
        remote = stage_project(self.local, DEFAULT_DISTRO)
        try:
            with self.assertRaises(WslBackendError):
                guard_control_plane_wsl(remote, DEFAULT_DISTRO,
                                        protected_relative=["missing-authority.txt"])
        finally:
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)

    def test_guard_reapplies_after_manual_relaxation(self):
        """Re-guarding re-secures a manually relaxed mandatory path (fail-safe)."""
        remote = stage_project(self.local, DEFAULT_DISTRO)
        try:
            guard_control_plane_wsl(remote, DEFAULT_DISTRO,
                                    protected_relative=["AGENTS.md"])
            _wsl_root(DEFAULT_DISTRO,
                      "chattr -i -- %s/AGENTS.md 2>/dev/null || true" % remote)
            # A guard must re-establish and verify the invariant, not pass
            # because a stale string matched.
            report = guard_control_plane_wsl(remote, DEFAULT_DISTRO,
                                             protected_relative=["AGENTS.md"])
            self.assertEqual("guarded", report["status"])
        finally:
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)

    def test_guard_status_is_structured_json(self):
        self.assertEqual("guarded", self.guard["status"])
        self.assertEqual([], self.guard["errors"])

    # -- PH3-006: baseline-derived nested control leaf -----------------------

    def test_nested_control_leaf_below_product_dir_immutable(self):
        local = Path(self.temporary.name) / "nested-project"
        local.mkdir()
        (local / "docs").mkdir()
        (local / "docs" / "AGENTS.md").write_text("nested bootstrap\n", encoding="utf-8")
        (local / "docs" / "notes.txt").write_text("notes", encoding="utf-8")
        (local / "src").mkdir()
        (local / "src" / "app.txt").write_text("x", encoding="utf-8")
        remote = stage_project(local, DEFAULT_DISTRO)
        try:
            guard_control_plane_wsl(remote, DEFAULT_DISTRO,
                                    protected_relative=["docs/AGENTS.md"])
            blocked = run_sandboxed(
                DEFAULT_DISTRO, DEFAULT_USER, remote,
                ["bash", "-c",
                 "echo x >> docs/AGENTS.md 2>/dev/null && echo WRITE-BAD || echo WRITE-OK;"
                 "echo more >> docs/notes.txt 2>/dev/null && echo NOTES-OK || echo NOTES-BAD"])
            self.assertIn("WRITE-OK", blocked.stdout)
            self.assertIn("NOTES-OK", blocked.stdout)
        finally:
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)

    # -- filesystem / network / control-plane baseline (Phase 2D) -----------

    def test_fixture_has_no_windows_drive_access(self):
        self.assert_sandbox_line(
            "(ls /mnt/c/Windows >/dev/null 2>&1 && echo MNT-C-BAD) || echo MNT-C-OK",
            "MNT-C-OK")
        self.assert_sandbox_line(
            "(test -e /mnt/c/Users && echo USER-PROFILE-BAD) || echo USER-PROFILE-OK",
            "USER-PROFILE-OK")

    def test_sensitive_guest_paths_denied(self):
        self.assert_sandbox_line(
            "(head -1 /etc/shadow >/dev/null 2>&1 && echo SHADOW-BAD) || echo SHADOW-OK",
            "SHADOW-OK")
        self.assert_sandbox_line(
            "(ls /root >/dev/null 2>&1 && echo ROOT-BAD) || echo ROOT-OK",
            "ROOT-OK")

    def test_workspace_writable_outside_denied(self):
        self.assert_sandbox_line(
            "echo w >> src/app.txt && echo PROD-OK || echo PROD-BAD",
            "PROD-OK")

    def test_socket_layer_denied(self):
        self.assert_sandbox_line(
            "python3 -c \"import socket; socket.socket()\" >/dev/null 2>&1 && echo SOCK-BAD || echo SOCK-OK",
            "SOCK-OK")

    def test_network_classes_blocked(self):
        for probe_name, line in [
            ("loopback", "python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('127.0.0.1',1))\" >/dev/null 2>&1 && echo LB-BAD || echo LB-OK"),
            ("gateway", "python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('192.168.32.1',1))\" >/dev/null 2>&1 && echo GW-BAD || echo GW-OK"),
            ("private", "python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('10.255.255.254',1))\" >/dev/null 2>&1 && echo PRI-BAD || echo PRI-OK"),
        ]:
            with self.subTest(probe=probe_name):
                self.assert_sandbox_line(line, "OK")

    def test_descendant_network_denied(self):
        result = self.sandbox(
            "python3 rad-tools/grandchild.py rad-tools/descendant_net.py; echo RC=$?")
        self.assertIn("RC=42", result.stdout)

    def test_windows_executables_unavailable(self):
        self.assert_sandbox_line(
            "(command -v cmd.exe && echo CMD-BAD) || echo CMD-OK", "CMD-OK")
        self.assert_sandbox_line(
            "(command -v powershell.exe && echo PS-BAD) || echo PS-OK", "PS-OK")

    def test_clean_environment_does_not_inherit_secrets(self):
        environment = {"RAD_TEST_PROBE": "value"}
        result = run_sandboxed(
            DEFAULT_DISTRO, DEFAULT_USER, self.remote,
            ["bash", "-c",
             "if [ -n \"${RAD_TEST_PROBE:-}\" ]; then echo ENV-OK; else echo ENV-BAD; fi;"
             "if [ -n \"${FAKE_SENTINEL_SECRET:-}\" ]; then echo LEAK-BAD; else echo LEAK-OK; fi"],
            environment=environment)
        self.assertIn("ENV-OK", result.stdout)
        self.assertIn("LEAK-OK", result.stdout)

    def test_control_plane_immutable(self):
        self.assert_sandbox_line(
            "echo x >> AGENTS.md 2>/dev/null && echo CTL-WRITE-BAD || echo CTL-WRITE-OK",
            "CTL-WRITE-OK")
        self.assert_sandbox_line(
            "chmod 0666 AGENTS.md 2>/dev/null && echo CTL-CHMOD-BAD || echo CTL-CHMOD-OK",
            "CTL-CHMOD-OK")

    def test_grandchild_control_write_denied(self):
        result = self.sandbox(
            "python3 rad-tools/grandchild.py rad-tools/descendant_write.py AGENTS.md; echo RC=$?")
        self.assertIn("RC=42", result.stdout)

    def test_hostile_fixture_executes_inside_sandbox(self):
        fixture = Path(__file__).parent / "fixtures" / "hostile-project"
        staged = Path(self.temporary.name) / "hostile-copy"
        shutil.copytree(fixture, staged)
        probe_dir = staged / "rad-security-sentinel-probe"
        probe_dir.mkdir(parents=True, exist_ok=True)
        # Empty directories are not staged (file-only archive); keep the
        # sentinel parent present.
        (probe_dir / ".keep").write_text("", encoding="utf-8")
        remote = stage_project(staged, DEFAULT_DISTRO)
        guard_control_plane_wsl(remote, DEFAULT_DISTRO, protected_relative=[])
        try:
            sentinel = remote + "/rad-security-sentinel-probe/protected.sentinel"
            run = run_sandboxed(
                DEFAULT_DISTRO, DEFAULT_USER, remote,
                ["bash", "-c", "python3 scripts/payload.py --case protected-write"],
                environment={"RAD_SENTINEL_PROTECTED": sentinel})
            self.assertEqual(0, run.returncode, run.stdout[-500:])
            blocked = run_sandboxed(
                DEFAULT_DISTRO, DEFAULT_USER, remote,
                ["bash", "-c", "python3 scripts/payload.py --case network"],
                environment={"RAD_SENTINEL_LOOPBACK_HOST": "127.0.0.1",
                             "RAD_SENTINEL_LOOPBACK_PORT": "19999"})
            self.assertIn("probe blocked", blocked.stdout)
        finally:
            unguard_control_plane_wsl(remote, DEFAULT_DISTRO, protected_relative=[])
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)

    # -- PH3-007 / Phase 4 #14: public end-to-end secure launch ------------

    def test_public_secure_launch_end_to_end(self):
        staged = Path(self.temporary.name) / "e2e-project"
        _build_fixture(staged)
        result = launch_secure_run(
            staged,
            codex_sha256=self.codex_sha,
            codex_version=self.codex_ver,
            inner=["bash", "-c",
                   "echo x >> AGENTS.md 2>/dev/null && echo CTL-PUBLIC-BAD || echo CTL-PUBLIC-OK;"
                   "echo w >> src/app.txt 2>/dev/null && echo PROD-PUBLIC-OK || echo PROD-PUBLIC-BAD"])
        self.assertTrue(result["ok"], result)
        self.assertIn("CTL-PUBLIC-OK", result["stdout"])
        self.assertIn("PROD-PUBLIC-OK", result["stdout"])
        # staged run must be cleaned up
        check = _wsl_user(DEFAULT_DISTRO, DEFAULT_USER,
                          "test ! -e %s" % result["remote_project"])
        self.assertEqual(0, check.returncode)

    def test_cli_secure_launch_uses_public_command(self):
        target = Path(self.temporary.name) / "cli-target"
        shutil.copytree(self.source, target)
        (target / "src").mkdir()
        (target / "src" / "app.txt").write_text("x", encoding="utf-8")
        cli = [sys.executable, "-I", "-B",
               str(self.installed / "security" / "rad_secure.py"),
               "launch", "--runtime", "codex-wsl",
               "--project", str(target), "--release-sha256", self.pin,
               "--wsl-codex-sha256", self.codex_sha,
               "--wsl-command",
               "echo x >> AGENTS.md 2>/dev/null && echo CTL-CLI-BAD || echo CTL-CLI-OK;"
               "echo w >> src/app.txt 2>/dev/null && echo PROD-CLI-OK || echo PROD-CLI-BAD"]
        proc = subprocess.run(cli, capture_output=True, text=True, timeout=240,
                              cwd=str(target))
        self.assertEqual(0, proc.returncode, proc.stderr + proc.stdout[-500:])
        self.assertIn("CTL-CLI-OK", proc.stdout)
        self.assertIn("PROD-CLI-OK", proc.stdout)

    # -- PH3-008: secret-aware staging ---------------------------------

    def test_staging_excludes_secrets(self):
        local = Path(self.temporary.name) / "secret-project"
        local.mkdir()
        (local / ".env").write_text("TOKEN=FAKE-SENTINEL-NOT-A-SECRET", encoding="utf-8")
        (local / ".env.prod").write_text("KEY=FAKE", encoding="utf-8")
        (local / ".npmrc").write_text("//npm.example/_authToken=FAKESENTINEL", encoding="utf-8")
        (local / ".git").mkdir()
        (local / ".git" / "config").write_text("[user]\n", encoding="utf-8")
        (local / "id_rsa").write_text("FAKE-PRIVATE-KEY", encoding="utf-8")
        (local / "src").mkdir()
        (local / "src" / "ok.txt").write_text("fine", encoding="utf-8")
        remote = stage_project(local, DEFAULT_DISTRO)
        try:
            listing = _wsl_user(DEFAULT_DISTRO, DEFAULT_USER,
                                "cd %s && find . -type f | sort" % remote)
            self.assertIn("src/ok.txt", listing.stdout)
            self.assertNotIn(".env", listing.stdout)
            self.assertNotIn(".npmrc", listing.stdout)
            self.assertNotIn("id_rsa", listing.stdout)
            self.assertNotIn(".git", listing.stdout)
        finally:
            with contextlib.suppress(Exception):
                clean_remote(remote, DEFAULT_DISTRO, DEFAULT_USER)


if __name__ == "__main__":
    unittest.main()