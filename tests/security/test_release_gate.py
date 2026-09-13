"""Portable release-gate regressions: CI/documentation/version consistency,
policy-vs-adapter permission consistency, manifest structure, stale generated
adapter detection, WSL helper parsing and guard entry-counting behavior.

These tests run on any OS; they never require the WSL distro or produce real
network/security side effects.
"""

import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from security.rad_security.policy import FileClass, Role, classify_path
from security.rad_security.guard import GuardError, control_plane_entries
from security.rad_security.wsl_backend import (_build_sandbox_environment,
                                              WslBackendError)
import tools.generate_adapters as gen

MARKDOWN_SUFFIXES = (".md",)


def _iter_repo_markdown():
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        yield path
    for path in ROOT.rglob("*.yml"):
        if ".github" in path.parts:
            yield path


class ReleaseGateTests(unittest.TestCase):
    # -- P0-1: workflow YAML validity -----------------------------------

    def test_workflows_parse_as_yaml(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")
        yaml = __import__("yaml")
        candidates = list((ROOT / ".github" / "workflows").glob("*.yml"))
        candidates += list((ROOT / ".github" / "workflows").glob("*.yaml"))
        self.assertGreater(len(candidates), 0, "no workflow files found")
        for path in candidates:
            with self.subTest(workflow=path.name):
                with path.open(encoding="utf-8") as fh:
                    document = yaml.safe_load(fh)
                self.assertIsInstance(document, dict)

    # -- P1-1: documentation-local link integrity -----------------------

    def test_documentation_links_resolve(self):
        link_re = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
        problems = []
        for path in _iter_repo_markdown():
            if path.suffix not in MARKDOWN_SUFFIXES:
                continue
            if "node_modules" in path.parts or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for match in link_re.finditer(text):
                target = match.group(1)
                if not target or target.startswith(("#", "http://", "https://",
                                                    "mailto:", "//", "/")):
                    continue
                if "://" in target or "%" in target:
                    continue
                if target.startswith("."):
                    continue
                resolved_local = (path.parent / target).resolve()
                resolved_root = (ROOT / target).resolve()
                if not (resolved_local.exists() or resolved_root.exists()):
                    problems.append("%s -> %s" % (path.relative_to(ROOT), target))
        self.assertEqual([], problems,
                         "dead documentation links: %s" % "; ".join(problems[:10]))

    # -- P1-2: version identity ------------------------------------------

    def test_version_identity_consistent(self):
        manifest = json.loads((ROOT / ".rad" / "manifest.json").read_text(encoding="utf-8"))
        version = manifest["rad_version"]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        contents = (ROOT / "PACKAGE_CONTENTS.md").read_text(encoding="utf-8")
        self.assertIn(version, readme, "README must advertise the manifest version")
        self.assertIn("## %s" % version, changelog,
                      "CHANGELOG must lead with the current version")
        self.assertIn(version, contents, "PACKAGE_CONTENTS must carry the version")

    # -- P1-4 / SF-1: adapter permissions match security policy ---------

    def test_adapter_permissions_consistent_with_policy(self):
        role_by_agent = {
            "orchestrator": Role.ORCHESTRATOR,
            "frontend-dev": Role.FRONTEND_DEV,
            "backend-dev": Role.BACKEND_DEV,
            "qa": Role.QA,
            "adversary": Role.ADVERSARY,
        }
        agents_dir = ROOT / ".opencode" / "agents"
        entry_re = re.compile(r'"([^"]+)"\s*:\s*(allow|deny)')
        problems = []
        for agent_file in agents_dir.glob("*.md"):
            agent = agent_file.stem
            role = role_by_agent.get(agent)
            if role is None:
                continue
            text = agent_file.read_text(encoding="utf-8")
            for match in entry_re.finditer(text):
                path, decision = match.group(1), match.group(2)
                if "*" in path or path.endswith("/"):
                    continue  # globs checked via exact control entries below
                try:
                    file_class = classify_path(path)
                except Exception:
                    continue
                if decision == "allow":
                    if file_class in (FileClass.CONTROL_PLANE,
                                      FileClass.GENERATED_CONTROL_OUTPUT):
                        problems.append("%s allows control path %s" % (agent, path))
            if agent == "orchestrator":
                if re.search(r'"DECISIONS\.md"\s*:\s*allow', text):
                    problems.append("orchestrator allows DECISIONS.md")
        self.assertEqual([], problems, "; ".join(problems[:10]))

    def test_codex_agents_declare_trusted_only(self):
        role = (ROOT / ".codex" / "agents" / "backend-dev.toml").read_text(encoding="utf-8")
        self.assertIn("TRUSTED-PROJECT ONLY", role)

    # -- Phase 6: manifest structure --------------------------------------

    def test_manifest_structure_valid(self):
        manifest = json.loads((ROOT / ".rad" / "manifest.json").read_text(encoding="utf-8"))
        for key in ("schema_version", "rad_version", "product_contract",
                    "core_protocol", "orchestrator_role", "roles", "workflows",
                    "policies", "command_policy"):
            self.assertIn(key, manifest, "manifest missing required key %s" % key)
        for name, entry in manifest["roles"].items():
            self.assertIsInstance(entry, dict)
            self.assertIn("path", entry)
            self.assertTrue((ROOT / entry["path"]).is_file(),
                            "role file missing: %s" % entry["path"])
        for workflow in manifest["workflows"].values():
            self.assertTrue((ROOT / workflow).is_file(),
                            "workflow file missing: %s" % workflow)
        for policy in manifest["policies"]:
            self.assertTrue((ROOT / policy).is_file(), "policy missing: %s" % policy)
        self.assertTrue((ROOT / manifest["command_policy"]).is_file())

    # -- Phase 5: stale generated adapters -------------------------------

    def test_no_stale_generated_adapters(self):
        stale = gen.stale_generated_files(["codex", "opencode", "claude", "cursor"])
        self.assertEqual([], stale)

    def test_marker_detection_works(self):
        self.assertTrue(gen._marker_in(".opencode/README.md"))
        self.assertFalse(gen._marker_in("README.md"))

    # -- P2-4: WSL exact distro matching --------------------------------

    def test_distro_exists_uses_exact_name(self):
        from security.rad_security import wsl_backend as wb
        listing = (
            "  NAME   STATE VERSION\n"
            "* docker-desktop  Stopped 2\n"
            "  RAD-Secure-Test Stopped 2\n"
            "  RAD-Secure-Test-Aux Stopped 2\n"
        )
        with mock.patch.object(wb, "_wsl") as fake_wsl:
            fake_wsl.return_value = wb._CompletedResult(0, listing)
            self.assertTrue(wb.distro_exists("RAD-Secure-Test"))
            self.assertFalse(wb.distro_exists("RAD-Secure-Test-Aux2"))
            self.assertTrue(wb.distro_exists("RAD-Secure-Test-Aux"))
            self.assertFalse(wb.distro_exists("RAD-Secure-Test-Z"))

    # -- P2-5: sandbox environment validation ---------------------------

    def test_sandbox_environment_validates_names_and_keeps_equals(self):
        env = _build_sandbox_environment("radtest", {"MY_TOKEN": "a=b=c",
                                                     "SPACED": "x y"})
        self.assertEqual("a=b=c", env["MY_TOKEN"])
        self.assertEqual("x y", env["SPACED"])
        for bad in ("", "1ABC", "A-B", "A.B", "A B"):
            with self.subTest(name=bad), self.assertRaises(WslBackendError):
                _build_sandbox_environment("radtest", {bad: "v"})
        with self.assertRaises(WslBackendError):
            _build_sandbox_environment("radtest", {"OK": "a\nb"})

    # -- P1-5: guard protected-entry counting ---------------------------

    def test_guard_counts_only_protected_entries(self):
        with tempfile.TemporaryDirectory(prefix="rad-gcap-") as directory:
            root = Path(directory).resolve()
            (root / "node_modules").mkdir()
            for i in range(20):
                (root / "node_modules" / ("pkg%s" % i)).mkdir()
                (root / "node_modules" / ("pkg%s" % i) / "f.txt").write_text("x")
            (root / "AGENTS.md").write_text("bootstrap\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "AGENTS.md").write_text("nested\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("x", encoding="utf-8")
            files, dirs = control_plane_entries(root)
            self.assertIn("AGENTS.md", {f.relative_to(root).as_posix() for f in files})
            self.assertIn("docs/AGENTS.md", {f.relative_to(root).as_posix() for f in files})
            self.assertNotIn(root / "node_modules", dirs)
            self.assertLess(len(files), 10)

    def test_guard_protected_limit_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="rad-glim-") as directory:
            root = Path(directory).resolve()
            (root / ".rad").mkdir()
            for i in range(2100):
                (root / ".rad" / ("%d" % i)).write_text("x", encoding="utf-8")
            with self.assertRaises(GuardError):
                control_plane_entries(root, protected_relative=None)

    # -- Phase 4 test gap: wrapper argument forwarding -------------------

    def test_no_private_email_in_repository_content(self):
        private_address = "github" + "@" + "daves-web.de"
        tracked = subprocess.run(["git", "ls-files"], capture_output=True,
                                 text=True, cwd=str(ROOT), check=True).stdout.splitlines()
        hits = []
        for rel in tracked:
            path = ROOT / rel
            if "node_modules" in path.parts:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if private_address.encode("utf-8") in data:
                hits.append(rel.as_posix() if hasattr(rel, "as_posix") else rel)
        self.assertEqual([], hits, "private email present in: %s" % "; ".join(hits[:10]))

    @unittest.skipUnless(os.name != "nt" and shutil.which("bash") and shutil.which("python3"),
                         "POSIX bash and python3 required")
    def test_generate_adapters_sh_check(self):
        result = subprocess.run(["bash", str(ROOT / "scripts" / "generate-adapters.sh"),
                                 "--check", "--all"],
                                cwd=str(ROOT), capture_output=True, text=True,
                                timeout=120)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("in sync", result.stdout)


if __name__ == "__main__":
    unittest.main()