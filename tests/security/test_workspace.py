import os
from pathlib import Path
import tempfile
import unittest

from security.rad_security.policy import Role, SecurityPolicyError
from security.rad_security.workspace import ProductWorkspace, _locked_parents


@unittest.skipUnless(os.name == "nt", "Windows handle-enforced workspace broker")
class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rad-security-sentinel-")
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "project"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "e2e").mkdir()
        self.workspace = ProductWorkspace(self.root, Role.BACKEND_DEV)

    def tearDown(self):
        self.temporary.cleanup()

    def test_allowed_product_edit_and_read(self):
        self.workspace.write("src/app.py", b"product data")
        self.assertEqual(b"product data", self.workspace.read("src/app.py"))

    def test_control_aliases_and_traversal_denied(self):
        for path in ("AGENTS.md", "agents.md", ".RAD/core/policy", "tools/generate_adapters.py",
                     ".github/workflows/build.yml", "DECISIONS.md", "nested/CLAUDE.md",
                     "../host.sentinel", "src/file:stream", "src/GENERA~1.PY"):
            with self.subTest(path=path), self.assertRaises(SecurityPolicyError):
                self.workspace.write(path, b"blocked")

    def test_parent_cannot_be_renamed_during_operation(self):
        with _locked_parents(self.root, "src/app.py"):
            with self.assertRaises(OSError):
                os.rename(self.root / "src", self.root / "replaced")

    def test_hardlink_to_host_sentinel_not_read_or_written(self):
        host = self.base / "host.sentinel"
        host.write_bytes(b"host remains unchanged")
        os.link(host, self.root / "src/linked")
        with self.assertRaises(SecurityPolicyError):
            self.workspace.read("src/linked")
        with self.assertRaises(SecurityPolicyError):
            self.workspace.write("src/linked", b"blocked")
        self.assertEqual(b"host remains unchanged", host.read_bytes())

    def test_symlink_to_host_sentinel_not_followed(self):
        host = self.base / "host.sentinel"
        host.write_bytes(b"host remains unchanged")
        try:
            os.symlink(host, self.root / "src/linked")
        except OSError:
            self.skipTest("host does not permit creation of a symlink fixture")
        with self.assertRaises(SecurityPolicyError):
            self.workspace.read("src/linked")
        with self.assertRaises(SecurityPolicyError):
            self.workspace.write("src/linked", b"blocked")
        self.assertEqual(b"host remains unchanged", host.read_bytes())

    def test_qa_can_write_e2e_developer_cannot(self):
        with self.assertRaises(SecurityPolicyError):
            self.workspace.write("e2e/test.py", b"blocked")
        ProductWorkspace(self.root, Role.QA).write("e2e/test.py", b"qa test")
        with self.assertRaises(SecurityPolicyError):
            ProductWorkspace(self.root, Role.QA).write("src/app.py", b"blocked")

    def test_environment_file_is_not_readable(self):
        (self.root / ".env").write_text("FAKE-SENTINEL-NOT-SECRET")
        with self.assertRaises(SecurityPolicyError):
            self.workspace.read(".env")


if __name__ == "__main__":
    unittest.main()
