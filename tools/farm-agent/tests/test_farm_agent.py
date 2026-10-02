import importlib.util
import tempfile
import unittest
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1] / "farm_agent.py"
spec = importlib.util.spec_from_file_location("farm_agent", AGENT)
farm_agent = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(farm_agent)


class BootstrapTests(unittest.TestCase):
    def test_hash(self):
        self.assertEqual(farm_agent.sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_base_sha(self):
        farm_agent.check_base_sha("a"*40, "a"*40)
        with self.assertRaises(farm_agent.AgentError) as e:
            farm_agent.check_base_sha("a"*40, "b"*40)
        self.assertEqual(e.exception.code, "BASE_SHA_MISMATCH")

    def test_path_traversal(self):
        for p in ("../x", "/etc/passwd", "a/../b", "C:/x", "a//b", "a/./b"):
            with self.subTest(p=p), self.assertRaises(farm_agent.AgentError):
                farm_agent.normalize_repo_path(p)

    def test_protected_paths(self):
        with self.assertRaises(farm_agent.AgentError) as e:
            farm_agent.validate_changed_paths([".github/workflows/x.yml"], [".github"])
        self.assertEqual(e.exception.code, "PROTECTED_PATH")

    def test_scope(self):
        self.assertEqual(farm_agent.validate_changed_paths(["src/a.ts"], ["src"]), ["src/a.ts"])
        with self.assertRaises(farm_agent.AgentError) as e:
            farm_agent.validate_changed_paths(["content/a.json"], ["src"])
        self.assertEqual(e.exception.code, "SCOPE_VIOLATION")

    def test_trusted_tools_scope(self):
        self.assertEqual(
            farm_agent.validate_changed_paths(["tools/farm-agent/README.md"], ["tools/farm-agent"], trusted_tools_change=True),
            ["tools/farm-agent/README.md"],
        )

    def test_request_id(self):
        self.assertEqual(farm_agent.request_id_decision(None, "abc"), "NEW")
        self.assertEqual(farm_agent.request_id_decision("abc", "abc"), "REUSE")
        with self.assertRaises(farm_agent.AgentError) as e:
            farm_agent.request_id_decision("abc", "def")
        self.assertEqual(e.exception.code, "REQUEST_ID_CONFLICT")

    def test_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = farm_agent.safe_workspace_path(root, "src/a.ts")
            p.relative_to(root)


if __name__ == "__main__":
    unittest.main()
