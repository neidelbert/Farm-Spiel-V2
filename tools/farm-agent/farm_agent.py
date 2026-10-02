#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional

VERSION = "1.0.0-v2.1"
EXPECTED_REPOSITORY = "neidelbert/Farm-Spiel-V2"
TARGET_BRANCH = "develop"
TICKET_FORMAT = "farm-ticket-v2"
PAYLOAD_ENCODING = "gzip+base64url"
MANIFEST_SCHEMA_VERSION = 2

PROTECTED_PREFIXES = (".github/", "tools/farm-agent/", ".git/")
ALLOWED_CHANGE_TYPES = {
    "ENGINE_CHANGE",
    "GAMEPLAY_CHANGE",
    "CONTENT_CHANGE",
    "MAP_CHANGE",
    "UI_CHANGE",
    "DOCS_CHANGE",
    "TEST_CHANGE",
    "MIXED_FOUNDATION_CHANGE",
}
ALLOWED_VALIDATORS = {
    "git-diff-check",
    "json-parse",
    "python-compile",
    "npm-typecheck",
    "npm-build",
    "registry-validator",
    "map-validator",
    "collision-validator",
    "navigation-validator",
}
ALLOWED_TESTS = {
    "npm-test",
}
NPM_SCRIPT_MAP = {
    "npm-typecheck": "typecheck",
    "npm-build": "build",
    "npm-test": "test",
    "registry-validator": "validate:registry",
    "map-validator": "validate:map",
    "collision-validator": "validate:collision",
    "navigation-validator": "validate:navigation",
}

MAX_TICKET_JSON_BYTES = 1_000_000
MAX_PAYLOAD_CHARS = 25_000_000
MAX_MANIFEST_BYTES = 30_000_000
MAX_PARTS = 512
MAX_PART_CHARS = 48_000
MAX_FILES = 200
MAX_FILE_BYTES = 10_000_000
MAX_TOTAL_FILE_BYTES = 25_000_000
MAX_REQUEST_ID_LEN = 128

REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}")
SHA40_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TICKET_RE = re.compile(r"FS-\d{3}")
B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
COMMIT_SUBJECT_RE = re.compile(r"FS-\d{3}: [^\r\n]{1,120}")


class AgentError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def fail(code: str, message: str) -> None:
    raise AgentError(code, message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        msg = f"command failed ({result.returncode}): {' '.join(args)}"
        if result.stdout.strip():
            msg += f"\nstdout:\n{result.stdout[-4000:]}"
        if result.stderr.strip():
            msg += f"\nstderr:\n{result.stderr[-4000:]}"
        fail("COMMAND_FAILED", msg)
    return result


def emit_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2))


def write_github_outputs(path: Optional[str], values: dict[str, Any]) -> None:
    if not path:
        return
    p = Path(path)
    with p.open("a", encoding="utf-8") as f:
        for key, value in values.items():
            if value is None:
                value = ""
            if isinstance(value, bool):
                value = "true" if value else "false"
            f.write(f"{key}={value}\n")


def ensure_exact_keys(obj: dict[str, Any], *, required: set[str], optional: set[str], label: str) -> None:
    keys = set(obj)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        fail("SCHEMA_INVALID", f"{label}: missing keys {sorted(missing)}")
    if unknown:
        fail("SCHEMA_INVALID", f"{label}: unknown keys {sorted(unknown)}")


def normalize_repo_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        fail("PATH_INVALID", "empty path")
    if "\x00" in raw:
        fail("PATH_INVALID", "NUL byte")
    if "\\" in raw:
        fail("PATH_INVALID", "backslashes are not allowed")
    if raw.startswith("/"):
        fail("PATH_TRAVERSAL", "absolute path")
    first = raw.split("/", 1)[0]
    if ":" in first:
        fail("PATH_TRAVERSAL", "drive/absolute-like path")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("PATH_TRAVERSAL", raw)
    normalized = PurePosixPath(raw).as_posix()
    if normalized != raw:
        fail("PATH_INVALID", raw)
    return normalized


def is_protected(path: str) -> bool:
    p = normalize_repo_path(path)
    return any(p == prefix.rstrip("/") or p.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def path_in_scope(path: str, scopes: Iterable[str]) -> bool:
    p = normalize_repo_path(path)
    for raw in scopes:
        scope = normalize_repo_path(raw.rstrip("/"))
        if p == scope or p.startswith(scope + "/"):
            return True
    return False


def validate_scope_path(path: str, scopes: list[str]) -> str:
    p = normalize_repo_path(path)
    if is_protected(p):
        fail("PROTECTED_PATH", p)
    if not path_in_scope(p, scopes):
        fail("SCOPE_VIOLATION", p)
    return p


def assert_no_symlink_chain(repo_root: Path, rel: str) -> Path:
    rel = normalize_repo_path(rel)
    root = repo_root.resolve()
    current = root
    parts = PurePosixPath(rel).parts
    for part in parts:
        current = current / part
        if current.is_symlink():
            fail("SYMLINK_ESCAPE", rel)
        if current.exists():
            resolved = current.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise AgentError("SYMLINK_ESCAPE", rel) from exc
    parent = (root / rel).parent.resolve(strict=False)
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise AgentError("SYMLINK_ESCAPE", rel) from exc
    return root / rel


def reject_repo_symlinks(repo_root: Path) -> None:
    for p in repo_root.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_symlink():
            fail("SYMLINK_PRESENT", str(p.relative_to(repo_root)))


def decode_b64url(value: str, *, code: str) -> bytes:
    if not isinstance(value, str) or not B64URL_RE.fullmatch(value):
        fail(code, "invalid base64url")
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise AgentError(code, f"invalid base64url: {exc}") from exc


def bounded_gzip_decode(compressed: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as gz:
            raw = gz.read(MAX_MANIFEST_BYTES + 1)
    except Exception as exc:
        raise AgentError("PAYLOAD_DECODE_FAILED", f"gzip: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        fail("PAYLOAD_TOO_LARGE", "manifest exceeds limit")
    return raw


def _validate_header_common(ticket: dict[str, Any], *, allow_missing_parts: bool) -> dict[str, Any]:
    required = {
        "format",
        "ticket",
        "action",
        "repository",
        "targetBranch",
        "baseSha",
        "changeType",
        "requestId",
        "payloadEncoding",
        "payloadLength",
        "payloadSha256",
        "transport",
        "payloadPartSha256",
    }
    if not allow_missing_parts:
        required.add("payloadParts")
    optional = {"payloadParts", "createdAt", "note"}
    ensure_exact_keys(ticket, required=required, optional=optional, label="ticket")

    if ticket["format"] != TICKET_FORMAT:
        fail("FORMAT_UNSUPPORTED", str(ticket["format"]))
    if not isinstance(ticket["ticket"], str) or not TICKET_RE.fullmatch(ticket["ticket"]):
        fail("TICKET_INVALID", str(ticket["ticket"]))
    if ticket["action"] not in ("INSTALL", "CLOSE"):
        fail("ACTION_INVALID", str(ticket["action"]))
    if ticket["repository"] != EXPECTED_REPOSITORY:
        fail("REPOSITORY_MISMATCH", str(ticket["repository"]))
    if ticket["targetBranch"] != TARGET_BRANCH:
        fail("BRANCH_MISMATCH", str(ticket["targetBranch"]))
    if not isinstance(ticket["baseSha"], str) or not SHA40_RE.fullmatch(ticket["baseSha"]):
        fail("BASE_SHA_INVALID", str(ticket["baseSha"]))
    if ticket["changeType"] not in ALLOWED_CHANGE_TYPES:
        fail("CHANGE_TYPE_INVALID", str(ticket["changeType"]))
    if not isinstance(ticket["requestId"], str) or not REQUEST_ID_RE.fullmatch(ticket["requestId"]):
        fail("REQUEST_ID_INVALID", str(ticket["requestId"]))
    if len(ticket["requestId"]) > MAX_REQUEST_ID_LEN:
        fail("REQUEST_ID_INVALID", "too long")
    if ticket["payloadEncoding"] != PAYLOAD_ENCODING:
        fail("PAYLOAD_ENCODING_INVALID", str(ticket["payloadEncoding"]))
    if ticket["transport"] not in ("INLINE", "MULTIPART"):
        fail("TRANSPORT_INVALID", str(ticket["transport"]))
    if not isinstance(ticket["payloadLength"], int) or not (1 <= ticket["payloadLength"] <= MAX_PAYLOAD_CHARS):
        fail("PAYLOAD_LENGTH_INVALID", str(ticket["payloadLength"]))
    if not isinstance(ticket["payloadSha256"], str) or not SHA256_RE.fullmatch(ticket["payloadSha256"]):
        fail("PAYLOAD_HASH_INVALID", str(ticket["payloadSha256"]))

    part_hashes = ticket["payloadPartSha256"]
    if not isinstance(part_hashes, list) or not (1 <= len(part_hashes) <= MAX_PARTS):
        fail("PART_COUNT_INVALID", "invalid payloadPartSha256 length")
    if any(not isinstance(x, str) or not SHA256_RE.fullmatch(x) for x in part_hashes):
        fail("PART_HASH_INVALID", "invalid part hash")
    if len(set(part_hashes)) != len(part_hashes) and len(part_hashes) > 1:
        # Duplicate hashes are allowed in theory, but for transport they almost always signal a duplicated part.
        fail("DUPLICATE_PART", "duplicate part hash")
    return ticket


def load_ticket_file(path: Path, *, allow_missing_parts: bool = False) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > MAX_TICKET_JSON_BYTES and not allow_missing_parts:
        fail("TICKET_TOO_LARGE", f"{len(data)} bytes")
    try:
        ticket = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise AgentError("TICKET_JSON_INVALID", str(exc)) from exc
    if not isinstance(ticket, dict):
        fail("TICKET_JSON_INVALID", "root must be object")
    return _validate_header_common(ticket, allow_missing_parts=allow_missing_parts)


def validate_ticket_object(ticket: dict[str, Any], *, allow_missing_parts: bool = False) -> dict[str, Any]:
    return _validate_header_common(ticket, allow_missing_parts=allow_missing_parts)


def decode_ticket_payload(ticket: dict[str, Any]) -> tuple[dict[str, Any], str]:
    parts = ticket.get("payloadParts")
    if not isinstance(parts, list) or not (1 <= len(parts) <= MAX_PARTS):
        fail("PART_COUNT_INVALID", "payloadParts missing/invalid")
    if len(parts) != len(ticket["payloadPartSha256"]):
        fail("PART_COUNT_INVALID", "part/hash count mismatch")

    for idx, part in enumerate(parts):
        if not isinstance(part, str) or not (1 <= len(part) <= MAX_PART_CHARS):
            fail("PART_LENGTH_INVALID", f"part {idx}")
        if not B64URL_RE.fullmatch(part):
            fail("PART_ENCODING_INVALID", f"part {idx}")
        actual = sha256_bytes(part.encode("ascii"))
        if actual != ticket["payloadPartSha256"][idx]:
            fail("PART_HASH_MISMATCH", f"part {idx}")

    payload_text = "".join(parts)
    if len(payload_text) != ticket["payloadLength"]:
        fail("PAYLOAD_LENGTH_MISMATCH", f"expected {ticket['payloadLength']} got {len(payload_text)}")
    if not B64URL_RE.fullmatch(payload_text):
        fail("PAYLOAD_ENCODING_INVALID", "joined payload")

    compressed = decode_b64url(payload_text, code="PAYLOAD_DECODE_FAILED")
    bundle_hash = sha256_bytes(compressed)
    if bundle_hash != ticket["payloadSha256"]:
        fail("BUNDLE_HASH_MISMATCH", f"expected {ticket['payloadSha256']} got {bundle_hash}")

    raw = bounded_gzip_decode(compressed)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AgentError("MANIFEST_JSON_INVALID", str(exc)) from exc
    if not isinstance(manifest, dict):
        fail("MANIFEST_JSON_INVALID", "root must be object")
    validate_manifest(manifest, ticket)
    return manifest, bundle_hash


def validate_manifest(manifest: dict[str, Any], ticket: dict[str, Any]) -> None:
    required = {
        "schemaVersion",
        "ticket",
        "action",
        "repository",
        "targetBranch",
        "baseSha",
        "commitMessage",
        "changeType",
        "allowedScopes",
        "operations",
        "expectedChangedFiles",
        "validators",
        "tests",
    }
    optional = {"reviewTargetSha", "description"}
    ensure_exact_keys(manifest, required=required, optional=optional, label="manifest")

    expected_pairs = {
        "ticket": ticket["ticket"],
        "action": ticket["action"],
        "repository": ticket["repository"],
        "targetBranch": ticket["targetBranch"],
        "baseSha": ticket["baseSha"],
        "changeType": ticket["changeType"],
    }
    if manifest.get("schemaVersion") != MANIFEST_SCHEMA_VERSION:
        fail("MANIFEST_SCHEMA_UNSUPPORTED", str(manifest.get("schemaVersion")))
    for key, expected in expected_pairs.items():
        if manifest.get(key) != expected:
            fail("MANIFEST_ENVELOPE_MISMATCH", f"{key}: {manifest.get(key)!r} != {expected!r}")

    if not isinstance(manifest["commitMessage"], str) or not COMMIT_SUBJECT_RE.fullmatch(manifest["commitMessage"]):
        fail("COMMIT_MESSAGE_INVALID", str(manifest["commitMessage"]))

    scopes = manifest["allowedScopes"]
    if not isinstance(scopes, list) or not scopes:
        fail("SCOPES_INVALID", "allowedScopes must be non-empty")
    normalized_scopes = []
    for scope in scopes:
        if not isinstance(scope, str):
            fail("SCOPES_INVALID", "scope must be string")
        n = normalize_repo_path(scope.rstrip("/"))
        if is_protected(n):
            fail("PROTECTED_PATH", n)
        normalized_scopes.append(n)
    if len(set(normalized_scopes)) != len(normalized_scopes):
        fail("SCOPES_INVALID", "duplicate scope")

    validators = manifest["validators"]
    tests = manifest["tests"]
    if not isinstance(validators, list) or any(v not in ALLOWED_VALIDATORS for v in validators):
        fail("VALIDATOR_INVALID", str(validators))
    if not isinstance(tests, list) or any(t not in ALLOWED_TESTS for t in tests):
        fail("TEST_INVALID", str(tests))
    if len(set(validators)) != len(validators) or len(set(tests)) != len(tests):
        fail("SCHEMA_INVALID", "duplicate validator/test")

    operations = manifest["operations"]
    if not isinstance(operations, list) or not (1 <= len(operations) <= MAX_FILES):
        fail("OPERATIONS_INVALID", "invalid operation count")

    paths: list[str] = []
    total_bytes = 0
    for idx, op in enumerate(operations):
        if not isinstance(op, dict):
            fail("OPERATIONS_INVALID", f"operation {idx}")
        action = op.get("action")
        if action not in ("write", "edit", "delete"):
            fail("OPERATION_INVALID", f"{idx}: {action}")
        required_op = {"action", "path", "preSha256", "postSha256"}
        optional_op = {"contentB64"}
        ensure_exact_keys(op, required=required_op, optional=optional_op, label=f"operation[{idx}]")

        path = op["path"]
        if not isinstance(path, str):
            fail("PATH_INVALID", str(path))
        p = validate_scope_path(path, normalized_scopes)
        if p in paths:
            fail("DUPLICATE_FILE_PATH", p)
        paths.append(p)

        pre = op["preSha256"]
        post = op["postSha256"]
        if action == "write":
            if pre is not None:
                fail("PRE_HASH_INVALID", f"{p}: new file must use null preSha256")
            if not isinstance(post, str) or not SHA256_RE.fullmatch(post):
                fail("POST_HASH_INVALID", p)
            content = _decode_content(op, p)
            total_bytes += len(content)
            if sha256_bytes(content) != post:
                fail("POST_HASH_MISMATCH", p)
        elif action == "edit":
            if not isinstance(pre, str) or not SHA256_RE.fullmatch(pre):
                fail("PRE_HASH_INVALID", p)
            if not isinstance(post, str) or not SHA256_RE.fullmatch(post):
                fail("POST_HASH_INVALID", p)
            content = _decode_content(op, p)
            total_bytes += len(content)
            if sha256_bytes(content) != post:
                fail("POST_HASH_MISMATCH", p)
        else:
            if not isinstance(pre, str) or not SHA256_RE.fullmatch(pre):
                fail("PRE_HASH_INVALID", p)
            if post is not None:
                fail("POST_HASH_INVALID", f"{p}: delete must use null postSha256")
            if "contentB64" in op:
                fail("SCHEMA_INVALID", f"{p}: delete must not include contentB64")

        if total_bytes > MAX_TOTAL_FILE_BYTES:
            fail("TOTAL_FILE_BYTES_EXCEEDED", str(total_bytes))

    expected = manifest["expectedChangedFiles"]
    if not isinstance(expected, list) or any(not isinstance(x, str) for x in expected):
        fail("EXPECTED_FILES_INVALID", str(expected))
    normalized_expected = [validate_scope_path(x, normalized_scopes) for x in expected]
    if len(set(normalized_expected)) != len(normalized_expected):
        fail("EXPECTED_FILES_INVALID", "duplicate file")
    if set(normalized_expected) != set(paths):
        fail("EXPECTED_FILES_MISMATCH", f"operations={sorted(paths)} expected={sorted(normalized_expected)}")

    if ticket["action"] == "CLOSE":
        review_sha = manifest.get("reviewTargetSha")
        if review_sha != ticket["baseSha"]:
            fail("CLOSE_TARGET_MISMATCH", f"reviewTargetSha={review_sha!r} baseSha={ticket['baseSha']!r}")
        if ticket["changeType"] != "DOCS_CHANGE":
            fail("CLOSE_CHANGE_TYPE_INVALID", ticket["changeType"])
    elif "reviewTargetSha" in manifest:
        fail("SCHEMA_INVALID", "INSTALL must not contain reviewTargetSha")


def _decode_content(op: dict[str, Any], path: str) -> bytes:
    value = op.get("contentB64")
    if not isinstance(value, str):
        fail("CONTENT_ENCODING_INVALID", path)
    try:
        content = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise AgentError("CONTENT_ENCODING_INVALID", f"{path}: {exc}") from exc
    if len(content) > MAX_FILE_BYTES:
        fail("FILE_TOO_LARGE", f"{path}: {len(content)}")
    return content


def git_head(repo_root: Path) -> str:
    return run(["git", "rev-parse", "HEAD"], cwd=repo_root).stdout.strip()


def git_status_paths(repo_root: Path) -> set[str]:
    changed = {
        line.strip()
        for line in run(["git", "diff", "--name-only"], cwd=repo_root).stdout.splitlines()
        if line.strip()
    }
    untracked = {
        line.strip()
        for line in run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=repo_root,
        ).stdout.splitlines()
        if line.strip()
    }
    deleted = {
        line.strip()
        for line in run(["git", "diff", "--name-only", "--diff-filter=D"], cwd=repo_root).stdout.splitlines()
        if line.strip()
    }
    return changed | untracked | deleted


def ensure_clean_repo(repo_root: Path) -> None:
    status = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo_root).stdout
    if status.strip():
        fail("WORKTREE_NOT_CLEAN", status[-4000:])


def find_request_record(repo_root: Path, request_id: str) -> tuple[Optional[str], Optional[str]]:
    # Restrict to the current develop history. Trailers are generated only by this agent.
    result = run(
        ["git", "log", "--format=%H%x1f%B%x1e"],
        cwd=repo_root,
    ).stdout
    for record in result.split("\x1e"):
        record = record.strip()
        if not record or "\x1f" not in record:
            continue
        sha, body = record.split("\x1f", 1)
        found_id = None
        found_bundle = None
        for line in body.splitlines():
            if line.startswith("Farm-Request-Id: "):
                found_id = line.removeprefix("Farm-Request-Id: ").strip()
            elif line.startswith("Farm-Bundle-Sha256: "):
                found_bundle = line.removeprefix("Farm-Bundle-Sha256: ").strip()
        if found_id == request_id:
            return found_bundle, sha.strip()
    return None, None


def request_decision(repo_root: Path, request_id: str, bundle_hash: str) -> tuple[str, Optional[str]]:
    existing_hash, existing_sha = find_request_record(repo_root, request_id)
    if existing_hash is None:
        return "NEW", None
    if existing_hash == bundle_hash:
        return "REUSE", existing_sha
    fail("REQUEST_ID_CONFLICT", f"requestId={request_id} existing={existing_hash} incoming={bundle_hash}")


def apply_manifest(repo_root: Path, ticket: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    ensure_clean_repo(repo_root)
    reject_repo_symlinks(repo_root)
    head = git_head(repo_root)
    if head != ticket["baseSha"]:
        fail("BASE_SHA_MISMATCH", f"expected={ticket['baseSha']} actual={head}")

    expected = set(manifest["expectedChangedFiles"])
    actual_paths: list[str] = []

    for op in manifest["operations"]:
        rel = op["path"]
        target = assert_no_symlink_chain(repo_root, rel)
        action = op["action"]

        if action == "write":
            if target.exists():
                fail("PRE_HASH_MISMATCH", f"{rel}: expected file to be absent")
            content = _decode_content(op, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            assert_no_symlink_chain(repo_root, rel)
            target.write_bytes(content)
            if sha256_file(target) != op["postSha256"]:
                fail("POST_HASH_MISMATCH", rel)

        elif action == "edit":
            if not target.exists() or not target.is_file():
                fail("PRE_HASH_MISMATCH", f"{rel}: file missing")
            actual_pre = sha256_file(target)
            if actual_pre != op["preSha256"]:
                fail("PRE_HASH_MISMATCH", f"{rel}: expected={op['preSha256']} actual={actual_pre}")
            content = _decode_content(op, rel)
            target.write_bytes(content)
            if sha256_file(target) != op["postSha256"]:
                fail("POST_HASH_MISMATCH", rel)

        elif action == "delete":
            if not target.exists() or not target.is_file():
                fail("PRE_HASH_MISMATCH", f"{rel}: file missing")
            actual_pre = sha256_file(target)
            if actual_pre != op["preSha256"]:
                fail("PRE_HASH_MISMATCH", f"{rel}: expected={op['preSha256']} actual={actual_pre}")
            target.unlink()

        actual_paths.append(rel)

    changed = git_status_paths(repo_root)
    if changed != expected:
        fail("UNEXPECTED_CHANGED_FILE", f"expected={sorted(expected)} actual={sorted(changed)}")

    run(["git", "diff", "--check"], cwd=repo_root)

    # Recheck all postconditions after the complete mutation set.
    for op in manifest["operations"]:
        rel = op["path"]
        target = assert_no_symlink_chain(repo_root, rel)
        if op["action"] == "delete":
            if target.exists() or target.is_symlink():
                fail("POST_HASH_MISMATCH", f"{rel}: still exists")
        else:
            if not target.exists() or sha256_file(target) != op["postSha256"]:
                fail("POST_HASH_MISMATCH", rel)
    return sorted(actual_paths)


def _clean_test_env() -> dict[str, str]:
    keep = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update({
        "CI": "true",
        "NODE_ENV": "test",
        "NO_COLOR": "1",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
    })
    return env


def _run_docker(repo_root: Path, args: list[str], *, network: str) -> None:
    if shutil.which("docker") is None:
        fail("TEST_ISOLATION_UNAVAILABLE", "docker is required on the validation runner")
    mount = f"{repo_root.resolve()}:/repo"
    cmd = [
        "docker", "run", "--rm",
        "--network", network,
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "2g",
        "--cpus", "2",
        "--pids-limit", "256",
        "--tmpfs", "/tmp:rw,nosuid,size=256m",
        "-v", mount,
        "-w", "/repo",
        "-e", "HOME=/tmp",
        "-e", "CI=true",
        "-e", "NODE_ENV=test",
        "-e", "NO_COLOR=1",
        "-e", "npm_config_cache=/tmp/.npm",
        "-e", "npm_config_audit=false",
        "-e", "npm_config_fund=false",
        "-e", "npm_config_update_notifier=false",
        "node:22.23.3-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c",
        *args,
    ]
    run(cmd)


def _package_scripts(repo_root: Path) -> dict[str, str]:
    package_json = repo_root / "package.json"
    if not package_json.exists():
        return {}
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentError("PACKAGE_JSON_INVALID", str(exc)) from exc
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        fail("PACKAGE_JSON_INVALID", "scripts must be object")
    return {str(k): str(v) for k, v in scripts.items()}


def run_validation_pipeline(repo_root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    validators = list(manifest["validators"])
    tests = list(manifest["tests"])
    completed: list[str] = []

    if "git-diff-check" not in validators:
        # Always mandatory, even if ticket forgot to request it.
        validators.insert(0, "git-diff-check")

    if "git-diff-check" in validators:
        run(["git", "diff", "--check"], cwd=repo_root)
        completed.append("git-diff-check")

    if "json-parse" in validators:
        for p in repo_root.rglob("*.json"):
            if ".git" in p.parts or "node_modules" in p.parts:
                continue
            try:
                json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                raise AgentError("JSON_INVALID", f"{p.relative_to(repo_root)}: {exc}") from exc
        completed.append("json-parse")

    if "python-compile" in validators:
        for p in repo_root.rglob("*.py"):
            if ".git" in p.parts or "node_modules" in p.parts:
                continue
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(p)],
                cwd=str(repo_root),
                env=_clean_test_env(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode != 0:
                fail("PYTHON_COMPILE_FAILED", f"{p.relative_to(repo_root)}: {result.stderr[-2000:]}")
        completed.append("python-compile")

    requested_npm = [x for x in validators + tests if x in NPM_SCRIPT_MAP]
    if requested_npm:
        package_json = repo_root / "package.json"
        lock = repo_root / "package-lock.json"
        if not package_json.exists():
            fail("PACKAGE_JSON_MISSING", "npm validator/test requested")
        if not lock.exists():
            fail("PACKAGE_LOCK_MISSING", "package-lock.json is required for deterministic validation")
        scripts = _package_scripts(repo_root)
        for item in requested_npm:
            script = NPM_SCRIPT_MAP[item]
            if script not in scripts:
                fail("NPM_SCRIPT_MISSING", f"{item} requires scripts.{script}")

        with tempfile.TemporaryDirectory(prefix="farm-test-sandbox-") as td:
            sandbox = Path(td) / "repo"
            shutil.copytree(
                repo_root,
                sandbox,
                ignore=shutil.ignore_patterns(".git", "node_modules", "dist", "coverage", ".vite"),
                symlinks=False,
            )
            # Dependency resolution is allowed only in the disposable, credential-free sandbox,
            # with install scripts disabled. User project scripts run afterwards with network disabled.
            _run_docker(
                sandbox,
                ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
                network="bridge",
            )
            for item in requested_npm:
                script = NPM_SCRIPT_MAP[item]
                _run_docker(
                    sandbox,
                    ["npm", "run", script],
                    network="none",
                )
                completed.append(item)

    return {
        "status": "PASS",
        "completed": completed,
        "validatorCount": len([x for x in completed if x in ALLOWED_VALIDATORS]),
        "testCount": len([x for x in completed if x in ALLOWED_TESTS]),
    }


def validate_ticket_against_repo(ticket_file: Path, repo_root: Path) -> dict[str, Any]:
    ticket = load_ticket_file(ticket_file)
    manifest, bundle_hash = decode_ticket_payload(ticket)

    decision, existing_sha = request_decision(repo_root, ticket["requestId"], bundle_hash)
    if decision == "REUSE":
        return {
            "ok": True,
            "mode": "VALIDATE",
            "decision": "REUSE",
            "ticket": ticket["ticket"],
            "action": ticket["action"],
            "requestId": ticket["requestId"],
            "bundleSha256": bundle_hash,
            "baseSha": ticket["baseSha"],
            "resultSha": existing_sha,
            "tests": {"status": "PASS", "completed": ["idempotent-reuse"], "validatorCount": 0, "testCount": 0},
        }

    head = git_head(repo_root)
    if head != ticket["baseSha"]:
        fail("REMOTE_MOVED", f"expected={ticket['baseSha']} actual={head}")

    applied = apply_manifest(repo_root, ticket, manifest)
    tests = run_validation_pipeline(repo_root, manifest)
    return {
        "ok": True,
        "mode": "VALIDATE",
        "decision": "NEW",
        "ticket": ticket["ticket"],
        "action": ticket["action"],
        "requestId": ticket["requestId"],
        "bundleSha256": bundle_hash,
        "baseSha": ticket["baseSha"],
        "resultSha": "",
        "changedFiles": applied,
        "tests": tests,
    }


def _remote_branch_sha(repo_root: Path) -> str:
    result = run(["git", "ls-remote", "origin", f"refs/heads/{TARGET_BRANCH}"], cwd=repo_root)
    line = result.stdout.strip()
    if not line:
        fail("REMOTE_BRANCH_MISSING", TARGET_BRANCH)
    sha = line.split()[0]
    if not SHA40_RE.fullmatch(sha):
        fail("REMOTE_SHA_INVALID", sha)
    return sha


def _git_auth_header(token: str) -> str:
    raw = f"x-access-token:{token}".encode("utf-8")
    return "AUTHORIZATION: basic " + base64.b64encode(raw).decode("ascii")


def publish_ticket(ticket_file: Path, repo_root: Path, token_env_name: str) -> dict[str, Any]:
    ticket = load_ticket_file(ticket_file)
    manifest, bundle_hash = decode_ticket_payload(ticket)

    decision, existing_sha = request_decision(repo_root, ticket["requestId"], bundle_hash)
    if decision == "REUSE":
        return {
            "ok": True,
            "mode": "PUBLISH",
            "decision": "REUSE",
            "ticket": ticket["ticket"],
            "action": ticket["action"],
            "requestId": ticket["requestId"],
            "bundleSha256": bundle_hash,
            "baseSha": ticket["baseSha"],
            "resultSha": existing_sha,
        }

    remote_before = _remote_branch_sha(repo_root)
    if remote_before != ticket["baseSha"]:
        fail("REMOTE_MOVED", f"expected={ticket['baseSha']} actual={remote_before}")
    if git_head(repo_root) != ticket["baseSha"]:
        fail("BASE_SHA_MISMATCH", f"expected={ticket['baseSha']} actual={git_head(repo_root)}")

    applied = apply_manifest(repo_root, ticket, manifest)

    run(["git", "config", "user.name", "Farm-Spiel Agent"], cwd=repo_root)
    run(["git", "config", "user.email", "farm-agent@users.noreply.github.com"], cwd=repo_root)

    expected = sorted(set(manifest["expectedChangedFiles"]))
    run(["git", "add", "-A", "--", *expected], cwd=repo_root)
    staged = {
        line.strip()
        for line in run(["git", "diff", "--cached", "--name-only"], cwd=repo_root).stdout.splitlines()
        if line.strip()
    }
    if staged != set(expected):
        fail("UNEXPECTED_CHANGED_FILE", f"staged expected={expected} actual={sorted(staged)}")

    full_message = (
        manifest["commitMessage"]
        + "\n\n"
        + f"Farm-Ticket: {ticket['ticket']}\n"
        + f"Farm-Action: {ticket['action']}\n"
        + f"Farm-Request-Id: {ticket['requestId']}\n"
        + f"Farm-Bundle-Sha256: {bundle_hash}\n"
        + f"Farm-Base-Sha: {ticket['baseSha']}\n"
    )
    run(["git", "commit", "-m", full_message], cwd=repo_root)
    result_sha = git_head(repo_root)
    parent_sha = run(["git", "rev-parse", "HEAD^"], cwd=repo_root).stdout.strip()
    if parent_sha != ticket["baseSha"]:
        fail("COMMIT_PARENT_MISMATCH", f"expected={ticket['baseSha']} actual={parent_sha}")

    committed = {
        line.strip()
        for line in run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
            cwd=repo_root,
        ).stdout.splitlines()
        if line.strip()
    }
    if committed != set(expected):
        fail("UNEXPECTED_CHANGED_FILE", f"committed expected={expected} actual={sorted(committed)}")

    remote_again = _remote_branch_sha(repo_root)
    if remote_again != ticket["baseSha"]:
        fail("REMOTE_MOVED", f"expected={ticket['baseSha']} actual={remote_again}")

    token = os.environ.get(token_env_name, "")
    if not token:
        fail("PUSH_TOKEN_MISSING", token_env_name)
    header = _git_auth_header(token)
    push = run(
        [
            "git",
            "-c", f"http.https://github.com/.extraheader={header}",
            "push",
            "origin",
            f"{result_sha}:refs/heads/{TARGET_BRANCH}",
        ],
        cwd=repo_root,
        check=False,
    )
    if push.returncode != 0:
        now = _remote_branch_sha(repo_root)
        if now != ticket["baseSha"]:
            fail("REMOTE_MOVED", f"expected={ticket['baseSha']} actual={now}")
        fail("PUSH_FAILED", (push.stderr or push.stdout)[-4000:])

    verify = _remote_branch_sha(repo_root)
    if verify != result_sha:
        fail("PUSH_VERIFICATION_FAILED", f"expected={result_sha} actual={verify}")

    return {
        "ok": True,
        "mode": "PUBLISH",
        "decision": "NEW",
        "ticket": ticket["ticket"],
        "action": ticket["action"],
        "requestId": ticket["requestId"],
        "bundleSha256": bundle_hash,
        "baseSha": ticket["baseSha"],
        "resultSha": result_sha,
        "changedFiles": applied,
    }


def validate_multipart_header(ticket: dict[str, Any]) -> dict[str, Any]:
    validate_ticket_object(ticket, allow_missing_parts=True)
    if ticket["transport"] != "MULTIPART":
        fail("TRANSPORT_INVALID", "multipart workflow requires MULTIPART")
    if "payloadParts" in ticket:
        fail("SCHEMA_INVALID", "multipart header must omit payloadParts")
    return ticket


def _artifact_name(request_id: str, index: int, part_sha: str) -> str:
    return f"farm-ticket-part-{request_id}-{index:03d}-{part_sha[:16]}"


def assemble_multipart(
    header_file: Path,
    output_file: Path,
    *,
    github_repository: str,
    token_env_name: str,
) -> dict[str, Any]:
    try:
        header = json.loads(header_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentError("TICKET_JSON_INVALID", str(exc)) from exc
    if not isinstance(header, dict):
        fail("TICKET_JSON_INVALID", "header root must be object")
    validate_multipart_header(header)
    if github_repository != EXPECTED_REPOSITORY:
        fail("REPOSITORY_MISMATCH", github_repository)

    token = os.environ.get(token_env_name, "")
    if not token:
        fail("ACTIONS_TOKEN_MISSING", token_env_name)

    parts: list[str] = []
    for idx, expected_hash in enumerate(header["payloadPartSha256"]):
        name = _artifact_name(header["requestId"], idx, expected_hash)
        q = urllib.parse.urlencode({"name": name, "per_page": "10"})
        url = f"https://api.github.com/repos/{github_repository}/actions/artifacts?{q}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Farm-Spiel-Agent",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                listing = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise AgentError("ARTIFACT_LOOKUP_FAILED", f"{name}: {exc}") from exc

        artifacts = [a for a in listing.get("artifacts", []) if a.get("name") == name and not a.get("expired")]
        if not artifacts:
            fail("MISSING_PART", f"part {idx}: {name}")
        artifacts.sort(key=lambda a: (a.get("created_at", ""), a.get("id", 0)), reverse=True)
        artifact = artifacts[0]
        download_url = artifact.get("archive_download_url")
        if not download_url:
            fail("ARTIFACT_LOOKUP_FAILED", f"{name}: no download URL")
        req2 = urllib.request.Request(
            download_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Farm-Spiel-Agent",
            },
        )
        try:
            with urllib.request.urlopen(req2, timeout=60) as resp:
                zip_bytes = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                if set(zf.namelist()) != {"meta.json", "part.txt"}:
                    fail("PART_ARTIFACT_INVALID", f"{name}: unexpected files {zf.namelist()}")
                meta = json.loads(zf.read("meta.json").decode("utf-8"))
                part = zf.read("part.txt").decode("ascii")
        except AgentError:
            raise
        except Exception as exc:
            raise AgentError("PART_ARTIFACT_INVALID", f"{name}: {exc}") from exc

        expected_meta = {
            "requestId": header["requestId"],
            "partIndex": idx,
            "partCount": len(header["payloadPartSha256"]),
            "partSha256": expected_hash,
            "bundleSha256": header["payloadSha256"],
        }
        for key, expected in expected_meta.items():
            if meta.get(key) != expected:
                fail("PART_METADATA_MISMATCH", f"{name}: {key}")
        if sha256_bytes(part.encode("ascii")) != expected_hash:
            fail("PART_HASH_MISMATCH", f"part {idx}")
        parts.append(part)

    ticket = dict(header)
    ticket["payloadParts"] = parts
    validate_ticket_object(ticket)
    # decode performs the total length + bundle hash checks.
    _, bundle_hash = decode_ticket_payload(ticket)
    output_file.write_text(json.dumps(ticket, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return {
        "ok": True,
        "mode": "ASSEMBLE",
        "requestId": header["requestId"],
        "partCount": len(parts),
        "bundleSha256": bundle_hash,
        "output": str(output_file),
    }


def internal_selftest(repo_root: Path) -> dict[str, Any]:
    checks: list[str] = []

    def mark(name: str) -> None:
        checks.append(name)

    def expect(name: str, code: str, fn) -> None:
        try:
            fn()
        except AgentError as exc:
            if exc.code != code:
                raise AssertionError(f"{name}: expected {code}, got {exc.code}") from exc
            mark(name)
            return
        raise AssertionError(f"{name}: expected {code}")

    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    mark("sha256")
    assert normalize_repo_path("src/game/a.ts") == "src/game/a.ts"
    mark("path_normalization")
    expect("path_parent_block", "PATH_TRAVERSAL", lambda: normalize_repo_path("../x"))
    expect("path_absolute_block", "PATH_TRAVERSAL", lambda: normalize_repo_path("/etc/passwd"))
    expect("protected_github", "PROTECTED_PATH", lambda: validate_scope_path(".github/x.yml", [".github"]))
    expect("protected_agent", "PROTECTED_PATH", lambda: validate_scope_path("tools/farm-agent/x.py", ["tools"]))
    validate_scope_path("src/a.ts", ["src"])
    mark("scope_allowed")
    expect("scope_violation", "SCOPE_VIOLATION", lambda: validate_scope_path("content/a.json", ["src"]))

    with tempfile.TemporaryDirectory(prefix="farm-agent-selftest-") as td:
        root = Path(td)
        (root / "safe").mkdir()
        outside = root.parent / (root.name + "-outside")
        outside.mkdir(exist_ok=True)
        link = root / "safe" / "escape"
        os.symlink(outside, link)
        expect("symlink_escape", "SYMLINK_ESCAPE", lambda: assert_no_symlink_chain(root, "safe/escape/x.txt"))
        link.unlink()
        try:
            outside.rmdir()
        except OSError:
            pass

    assert "force" not in " ".join(["git", "push", "origin", "HEAD:refs/heads/develop"]).lower()
    mark("non_force_push_contract")
    assert MAX_PART_CHARS < 60_000
    mark("dispatch_safe_part_size")
    assert TARGET_BRANCH == "develop" and EXPECTED_REPOSITORY.endswith("/Farm-Spiel-V2")
    mark("repo_branch_contract")

    return {
        "ok": True,
        "agentVersion": VERSION,
        "mode": "SELFTEST",
        "checks": checks,
        "checkCount": len(checks),
    }


def _main() -> int:
    parser = argparse.ArgumentParser(prog="farm_agent.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_self = sub.add_parser("selftest")
    p_self.add_argument("--repo-root", default=".")

    p_val = sub.add_parser("validate")
    p_val.add_argument("--ticket-file", required=True)
    p_val.add_argument("--repo-root", required=True)
    p_val.add_argument("--github-output")

    p_pub = sub.add_parser("publish")
    p_pub.add_argument("--ticket-file", required=True)
    p_pub.add_argument("--repo-root", required=True)
    p_pub.add_argument("--push-token-env", default="FARM_PUSH_TOKEN")
    p_pub.add_argument("--github-output")

    p_asm = sub.add_parser("assemble-multipart")
    p_asm.add_argument("--header-file", required=True)
    p_asm.add_argument("--output-file", required=True)
    p_asm.add_argument("--github-repository", required=True)
    p_asm.add_argument("--actions-token-env", default="FARM_ACTIONS_TOKEN")
    p_asm.add_argument("--github-output")

    args = parser.parse_args()
    try:
        if args.command == "selftest":
            report = internal_selftest(Path(args.repo_root))
        elif args.command == "validate":
            report = validate_ticket_against_repo(Path(args.ticket_file), Path(args.repo_root))
        elif args.command == "publish":
            report = publish_ticket(
                Path(args.ticket_file),
                Path(args.repo_root),
                args.push_token_env,
            )
        elif args.command == "assemble-multipart":
            report = assemble_multipart(
                Path(args.header_file),
                Path(args.output_file),
                github_repository=args.github_repository,
                token_env_name=args.actions_token_env,
            )
        else:
            fail("COMMAND_INVALID", args.command)

        outputs = {
            "ok": report.get("ok", False),
            "decision": report.get("decision", ""),
            "ticket": report.get("ticket", ""),
            "action": report.get("action", ""),
            "request_id": report.get("requestId", ""),
            "bundle_sha256": report.get("bundleSha256", ""),
            "base_sha": report.get("baseSha", ""),
            "result_sha": report.get("resultSha", ""),
            "part_count": report.get("partCount", ""),
        }
        write_github_outputs(getattr(args, "github_output", None), outputs)
        emit_json(report)
        return 0
    except AgentError as exc:
        report = {"ok": False, "code": exc.code, "message": exc.message, "agentVersion": VERSION}
        emit_json(report)
        return 2
    except Exception as exc:
        report = {
            "ok": False,
            "code": "AGENT_INTERNAL_ERROR",
            "message": f"{type(exc).__name__}: {exc}",
            "agentVersion": VERSION,
        }
        emit_json(report)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
