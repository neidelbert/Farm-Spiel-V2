#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

VERSION = "0.1.0-bootstrap"
PROTECTED_PREFIXES = (".github/", "tools/farm-agent/")


class AgentError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_base_sha(expected: str, actual: str) -> None:
    if not expected or not actual or expected != actual:
        raise AgentError("BASE_SHA_MISMATCH", f"expected={expected!r} actual={actual!r}")


def normalize_repo_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise AgentError("PATH_INVALID", "empty path")
    if "\x00" in raw:
        raise AgentError("PATH_INVALID", "NUL byte")
    if "\\" in raw:
        raise AgentError("PATH_INVALID", "backslashes are not allowed")
    if raw.startswith("/"):
        raise AgentError("PATH_TRAVERSAL", "absolute path")
    first = raw.split("/", 1)[0]
    if ":" in first:
        raise AgentError("PATH_TRAVERSAL", "drive/absolute-like path")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise AgentError("PATH_TRAVERSAL", raw)
    return PurePosixPath(raw).as_posix()


def is_protected(path: str) -> bool:
    p = normalize_repo_path(path)
    return any(p == x.rstrip("/") or p.startswith(x) for x in PROTECTED_PREFIXES)


def path_in_scope(path: str, allowed_scopes: Iterable[str]) -> bool:
    p = normalize_repo_path(path)
    for raw in allowed_scopes:
        scope = normalize_repo_path(raw.rstrip("/"))
        if p == scope or p.startswith(scope + "/"):
            return True
    return False


def validate_changed_paths(paths: Iterable[str], allowed_scopes: Iterable[str], *, trusted_tools_change: bool = False) -> list[str]:
    result = []
    for raw in paths:
        p = normalize_repo_path(raw)
        if is_protected(p) and not trusted_tools_change:
            raise AgentError("PROTECTED_PATH", p)
        if not path_in_scope(p, allowed_scopes):
            raise AgentError("SCOPE_VIOLATION", p)
        result.append(p)
    return result


def safe_workspace_path(repo_root: Path, relative_path: str) -> Path:
    rel = normalize_repo_path(relative_path)
    root = repo_root.resolve()
    candidate = root / rel
    parent = candidate.parent.resolve(strict=False)
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise AgentError("SYMLINK_ESCAPE", rel) from exc
    return candidate


def request_id_decision(existing_hash: Optional[str], incoming_hash: str) -> str:
    if not incoming_hash:
        raise AgentError("PAYLOAD_HASH_MISMATCH", "missing bundle hash")
    if existing_hash is None:
        return "NEW"
    if existing_hash == incoming_hash:
        return "REUSE"
    raise AgentError("REQUEST_ID_CONFLICT", "same requestId with different bundle hash")


def internal_selftest(repo_root: Path) -> dict:
    passed = []

    def mark(name):
        passed.append(name)

    def expect(name, code, fn):
        try:
            fn()
        except AgentError as exc:
            if exc.code != code:
                raise AssertionError(f"{name}: expected {code}, got {exc.code}") from exc
            mark(name)
            return
        raise AssertionError(f"{name}: expected {code}")

    check_base_sha("a"*40, "a"*40); mark("base_sha_match")
    expect("base_sha_mismatch", "BASE_SHA_MISMATCH", lambda: check_base_sha("a"*40, "b"*40))
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; mark("sha256")
    assert normalize_repo_path("src/game/a.ts") == "src/game/a.ts"; mark("path_normalization")
    expect("traversal_parent", "PATH_TRAVERSAL", lambda: normalize_repo_path("../x"))
    expect("traversal_absolute", "PATH_TRAVERSAL", lambda: normalize_repo_path("/etc/passwd"))
    expect("protected_github", "PROTECTED_PATH", lambda: validate_changed_paths([".github/workflows/x.yml"], [".github"]))
    expect("protected_agent", "PROTECTED_PATH", lambda: validate_changed_paths(["tools/farm-agent/x.py"], ["tools"]))
    validate_changed_paths(["src/game/a.ts"], ["src"]); mark("scope_allowed")
    expect("scope_violation", "SCOPE_VIOLATION", lambda: validate_changed_paths(["content/a.json"], ["src"]))
    assert request_id_decision(None, "abc") == "NEW"
    assert request_id_decision("abc", "abc") == "REUSE"; mark("request_id_idempotency")
    expect("request_id_conflict", "REQUEST_ID_CONFLICT", lambda: request_id_decision("abc", "def"))
    safe_workspace_path(repo_root, "README.md"); mark("workspace_path")

    test_dir = repo_root / ".farm-agent-selftest"
    outside = repo_root.parent / ".farm-agent-selftest-outside"
    try:
        test_dir.mkdir(exist_ok=True)
        outside.mkdir(exist_ok=True)
        link = test_dir / "escape"
        if link.exists() or link.is_symlink():
            link.unlink()
        os.symlink(outside, link)
        expect("symlink_escape", "SYMLINK_ESCAPE", lambda: safe_workspace_path(repo_root, ".farm-agent-selftest/escape/file.txt"))
    finally:
        try:
            if (test_dir / "escape").is_symlink():
                (test_dir / "escape").unlink()
            test_dir.rmdir()
        except OSError:
            pass
        try:
            outside.rmdir()
        except OSError:
            pass

    return {"ok": True, "agentVersion": VERSION, "mode": "SELFTEST", "checks": passed, "checkCount": len(passed)}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("selftest")
    p.add_argument("--repo-root", default=".")
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            print(json.dumps(internal_selftest(Path(args.repo_root)), indent=2, sort_keys=True))
            return 0
    except AgentError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}, indent=2))
        return 2
    except Exception as exc:
        print(json.dumps({"ok": False, "code": "SELFTEST_FAIL", "message": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
