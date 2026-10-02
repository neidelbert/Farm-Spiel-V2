import base64
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

AGENT_PATH = Path(__file__).resolve().parents[1] / "farm_agent.py"
spec = importlib.util.spec_from_file_location("farm_agent", AGENT_PATH)
farm_agent = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(farm_agent)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(root: Path, *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True)
    return r.stdout.strip()


def init_repo(root: Path) -> str:
    run_git(root, "init", "-b", "develop")
    run_git(root, "config", "user.name", "Test")
    run_git(root, "config", "user.email", "test@example.invalid")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    run_git(root, "add", "README.md")
    run_git(root, "commit", "-m", "base")
    return run_git(root, "rev-parse", "HEAD")


def build_ticket(
    base_sha: str,
    *,
    action: str = "INSTALL",
    operations=None,
    scopes=None,
    expected=None,
    validators=None,
    tests=None,
    request_id: str = "req-test-0001",
    change_type: str = "ENGINE_CHANGE",
    review_target_sha=None,
):
    operations = operations if operations is not None else []
    scopes = scopes if scopes is not None else ["src"]
    expected = expected if expected is not None else [op["path"] for op in operations]
    manifest = {
        "schemaVersion": 2,
        "ticket": "FS-001",
        "action": action,
        "repository": "neidelbert/Farm-Spiel-V2",
        "targetBranch": "develop",
        "baseSha": base_sha,
        "commitMessage": "FS-001: test change",
        "changeType": change_type,
        "allowedScopes": scopes,
        "operations": operations,
        "expectedChangedFiles": expected,
        "validators": validators if validators is not None else ["git-diff-check", "json-parse"],
        "tests": tests if tests is not None else [],
    }
    if review_target_sha is not None:
        manifest["reviewTargetSha"] = review_target_sha
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw, mtime=0)
    payload = base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
    parts = [payload[i:i+12000] for i in range(0, len(payload), 12000)]
    return {
        "format": "farm-ticket-v2",
        "ticket": "FS-001",
        "action": action,
        "repository": "neidelbert/Farm-Spiel-V2",
        "targetBranch": "develop",
        "baseSha": base_sha,
        "changeType": change_type,
        "requestId": request_id,
        "payloadEncoding": "gzip+base64url",
        "payloadLength": len(payload),
        "payloadSha256": sha(compressed),
        "transport": "INLINE",
        "payloadPartSha256": [sha(p.encode("ascii")) for p in parts],
        "payloadParts": parts,
    }


class FarmAgentTests(unittest.TestCase):
    def expect_code(self, code, fn):
        with self.assertRaises(farm_agent.AgentError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    def test_selftest(self):
        with tempfile.TemporaryDirectory() as td:
            report = farm_agent.internal_selftest(Path(td))
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["checkCount"], 12)

    def test_path_rules(self):
        self.assertEqual(farm_agent.normalize_repo_path("src/a.ts"), "src/a.ts")
        for bad in ("../x", "/x", "C:/x", "a//b", "a/./b", "a/../b", r"a\b"):
            with self.subTest(bad=bad):
                self.assertRaises(farm_agent.AgentError, farm_agent.normalize_repo_path, bad)

    def test_protected_paths(self):
        for p in (".github/workflows/x.yml", "tools/farm-agent/x.py", ".git/config"):
            with self.subTest(p=p):
                self.expect_code("PROTECTED_PATH", lambda p=p: farm_agent.validate_scope_path(p, [p.split("/")[0]]))

    def test_bundle_decode_and_hashes(self):
        content = b"export const x = 1;\n"
        op = {
            "action": "write",
            "path": "src/a.ts",
            "preSha256": None,
            "postSha256": sha(content),
            "contentB64": base64.b64encode(content).decode("ascii"),
        }
        ticket = build_ticket("a"*40, operations=[op])
        manifest, bundle = farm_agent.decode_ticket_payload(ticket)
        self.assertEqual(manifest["ticket"], "FS-001")
        self.assertEqual(bundle, ticket["payloadSha256"])

        bad = json.loads(json.dumps(ticket))
        bad["payloadSha256"] = "0"*64
        self.expect_code("BUNDLE_HASH_MISMATCH", lambda: farm_agent.decode_ticket_payload(bad))

        bad2 = json.loads(json.dumps(ticket))
        bad2["payloadPartSha256"][0] = "0"*64
        self.expect_code("PART_HASH_MISMATCH", lambda: farm_agent.decode_ticket_payload(bad2))

    def test_write_edit_delete_application(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = init_repo(root)

            new = b"hello\n"
            op = {
                "action": "write",
                "path": "src/a.txt",
                "preSha256": None,
                "postSha256": sha(new),
                "contentB64": base64.b64encode(new).decode("ascii"),
            }
            ticket = build_ticket(base, operations=[op], scopes=["src"])
            manifest, _ = farm_agent.decode_ticket_payload(ticket)
            paths = farm_agent.apply_manifest(root, ticket, manifest)
            self.assertEqual(paths, ["src/a.txt"])
            self.assertEqual((root/"src/a.txt").read_bytes(), new)

    def test_pre_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = init_repo(root)
            (root/"src").mkdir()
            (root/"src/a.txt").write_bytes(b"old")
            run_git(root, "add", "src/a.txt")
            run_git(root, "commit", "-m", "add")
            base = run_git(root, "rev-parse", "HEAD")

            content = b"new"
            op = {
                "action": "edit",
                "path": "src/a.txt",
                "preSha256": "0"*64,
                "postSha256": sha(content),
                "contentB64": base64.b64encode(content).decode("ascii"),
            }
            ticket = build_ticket(base, operations=[op])
            manifest, _ = farm_agent.decode_ticket_payload(ticket)
            self.expect_code("PRE_HASH_MISMATCH", lambda: farm_agent.apply_manifest(root, ticket, manifest))

    def test_unexpected_changed_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = init_repo(root)
            content = b"ok"
            op = {
                "action": "write",
                "path": "src/a.txt",
                "preSha256": None,
                "postSha256": sha(content),
                "contentB64": base64.b64encode(content).decode("ascii"),
            }
            ticket = build_ticket(base, operations=[op])
            manifest, _ = farm_agent.decode_ticket_payload(ticket)
            (root/"rogue.txt").write_text("rogue", encoding="utf-8")
            self.expect_code("WORKTREE_NOT_CLEAN", lambda: farm_agent.apply_manifest(root, ticket, manifest))

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/"src").mkdir()
            outside = root.parent / (root.name + "-outside")
            outside.mkdir(exist_ok=True)
            os.symlink(outside, root/"src/link")
            try:
                self.expect_code("SYMLINK_ESCAPE", lambda: farm_agent.assert_no_symlink_chain(root, "src/link/x.txt"))
            finally:
                (root/"src/link").unlink()
                outside.rmdir()

    def test_close_requires_review_sha_and_docs(self):
        base = "a"*40
        content = b"# close\n"
        op = {
            "action": "write",
            "path": "docs/tasks/FS-001.md",
            "preSha256": None,
            "postSha256": sha(content),
            "contentB64": base64.b64encode(content).decode("ascii"),
        }
        ticket = build_ticket(
            base,
            action="CLOSE",
            operations=[op],
            scopes=["docs"],
            change_type="DOCS_CHANGE",
            review_target_sha=base,
        )
        manifest, _ = farm_agent.decode_ticket_payload(ticket)
        self.assertEqual(manifest["reviewTargetSha"], base)

        bad = build_ticket(
            base,
            action="CLOSE",
            operations=[op],
            scopes=["docs"],
            change_type="DOCS_CHANGE",
            review_target_sha="b"*40,
        )
        self.expect_code("CLOSE_TARGET_MISMATCH", lambda: farm_agent.decode_ticket_payload(bad))

    def test_request_id_reuse_and_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            init_repo(root)
            bundle = "1"*64
            msg = (
                "FS-001: applied\n\n"
                "Farm-Ticket: FS-001\n"
                "Farm-Action: INSTALL\n"
                "Farm-Request-Id: req-reuse-0001\n"
                f"Farm-Bundle-Sha256: {bundle}\n"
            )
            (root/"README.md").write_text("changed\n", encoding="utf-8")
            run_git(root, "add", "README.md")
            run_git(root, "commit", "-m", msg)
            decision, sha1 = farm_agent.request_decision(root, "req-reuse-0001", bundle)
            self.assertEqual(decision, "REUSE")
            self.assertTrue(sha1)
            self.expect_code(
                "REQUEST_ID_CONFLICT",
                lambda: farm_agent.request_decision(root, "req-reuse-0001", "2"*64),
            )

    def test_manifest_rejects_unknown_keys(self):
        content = b"x"
        op = {
            "action": "write",
            "path": "src/a.txt",
            "preSha256": None,
            "postSha256": sha(content),
            "contentB64": base64.b64encode(content).decode("ascii"),
        }
        ticket = build_ticket("a"*40, operations=[op])
        # Tamper internal payload by decoding/re-encoding.
        compressed = base64.urlsafe_b64decode(ticket["payloadParts"][0] + "=" * (-len(ticket["payloadParts"][0]) % 4))
        manifest = json.loads(gzip.decompress(compressed))
        manifest["typoField"] = True
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        comp = gzip.compress(raw, mtime=0)
        payload = base64.urlsafe_b64encode(comp).decode().rstrip("=")
        ticket["payloadParts"] = [payload]
        ticket["payloadPartSha256"] = [sha(payload.encode())]
        ticket["payloadLength"] = len(payload)
        ticket["payloadSha256"] = sha(comp)
        self.expect_code("SCHEMA_INVALID", lambda: farm_agent.decode_ticket_payload(ticket))

    def test_part_size_contract(self):
        self.assertLess(farm_agent.MAX_PART_CHARS, 60000)
        self.assertGreaterEqual(farm_agent.MAX_PARTS * farm_agent.MAX_PART_CHARS, 20_000_000)


if __name__ == "__main__":
    unittest.main()
