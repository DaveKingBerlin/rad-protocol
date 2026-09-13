"""Maintenance-time adapter consistency, not proof of native runtime enforcement."""
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

from security.rad_security.policy import is_control_plane


ROOT = Path(__file__).resolve().parents[2]


class AdapterRegressionTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / ".rad/security/command-policy.json").read_text())
        self.manifest = json.loads((ROOT / ".rad/manifest.json").read_text())

    def test_canonical_shell_allowlist_is_empty(self):
        self.assertEqual([], self.policy["automatic_shell_commands"])
        self.assertEqual("ask", self.policy["trusted_project_shell_decision"])
        self.assertIs(True, self.policy["secure_mode_requires_installed_launcher"])

    def test_opencode_has_no_per_command_shell_allow(self):
        for path in (ROOT / ".opencode/agents").glob("*.md"):
            with self.subTest(path=path.name):
                frontmatter = path.read_text(encoding="utf-8").split("---", 2)[1]
                shell = frontmatter.split("  bash:\n", 1)[1]
                self.assertEqual('    "*": ask', shell.strip("\n"))
                self.assertNotRegex(shell, r":\s*allow\b")

    def test_developer_direct_edit_denials_cover_canonical_controls(self):
        for role in ("backend-dev", "frontend-dev"):
            frontmatter = (ROOT / f".opencode/agents/{role}.md").read_text(encoding="utf-8").split("---", 2)[1]
            for path in self.policy["control_plane_files"] + self.policy["control_plane_roots"]:
                with self.subTest(role=role, path=path):
                    self.assertIn(f'    "{path}": deny', frontmatter)
            keys = re.findall(r'^    "([^"]+)":', frontmatter.split("  bash:")[0], flags=re.M)
            self.assertEqual(len(keys), len(set(keys)), "duplicate permission key")

    def test_installed_policy_protects_every_canonical_control(self):
        for path in self.policy["control_plane_files"] + self.policy["control_plane_roots"]:
            with self.subTest(path=path):
                self.assertTrue(is_control_plane(path))

    def test_all_supported_roles_are_generated_for_each_runtime(self):
        for runtime in ("codex", "opencode", "claude", "cursor"):
            extension = "toml" if runtime == "codex" else "md"
            for role in self.manifest["roles"]:
                self.assertTrue((ROOT / f".{runtime}/agents/{role}.{extension}").is_file())

    def test_authorized_maintenance_generator_check(self):
        # This invocation is explicitly part of the reviewed maintenance suite;
        # it is never offered to an untrusted project as an automatic checker.
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/generate_adapters.py"),
                                 "--check", "--all"], capture_output=True, text=True,
                                timeout=30, cwd=ROOT, check=False)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
