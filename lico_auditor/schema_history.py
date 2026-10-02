"""Proof-bound historical schema source; never a current SQL/data-file exemption."""
from __future__ import annotations

import hashlib
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .models import Finding

MAX_DECLARATIONS = 32
MAX_SOURCE_BYTES = 262_144
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
SQL_TOKENS = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|--[^\n]*|/\*[\s\S]*?\*/")


@dataclass(frozen=True)
class SchemaHistoryDeclaration:
    path: str
    sha256: str
    successor: str
    constant: str
    producer_path: str
    producer_revision: str
    reason: str


def _path(value: object, suffix: str | None = None, *, fixture: bool = False) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,399}", value) is not None
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and not set(PurePosixPath(value).parts) & {".git", ".kilo", "build", "cache"}
        and (suffix is None or value.endswith(suffix))
        and (not fixture or value.startswith("tests/fixtures/"))
    )


def parse_declarations(value: object) -> tuple[SchemaHistoryDeclaration, ...]:
    if not isinstance(value, list) or len(value) > MAX_DECLARATIONS:
        raise ValueError("reviewedSchemaHistory must be a bounded list of exact declarations.")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "successor", "producer", "reason"}:
            raise ValueError("A reviewed schema requires exact path, sha256, successor, producer and reason fields.")
        successor, producer = item["successor"], item["producer"]
        if (
            not _path(item["path"], ".sql", fixture=True)
            or not isinstance(item["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
            or not isinstance(successor, dict) or set(successor) != {"path", "constant"}
            or not _path(successor["path"], ".rs", fixture=True)
            or not isinstance(successor["constant"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", successor["constant"])
            or not isinstance(producer, dict) or set(producer) != {"path", "revision"}
            or not _path(producer["path"], ".rs")
            or not isinstance(producer["revision"], str) or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", producer["revision"])
            or not isinstance(item["reason"], str) or not 20 <= len(item["reason"].strip()) <= 512
            or any(ord(char) < 32 for char in item["reason"])
        ):
            raise ValueError("Reviewed schema provenance must use exact bounded repository source paths, hashes and purpose.")
        key = (item["path"], item["sha256"])
        if key in seen:
            raise ValueError("Reviewed schema path/hash pairs must be unique.")
        seen.add(key)
        result.append(SchemaHistoryDeclaration(item["path"], item["sha256"], successor["path"], successor["constant"], producer["path"], producer["revision"], item["reason"].strip()))
    return tuple(result)


def schema_only(raw: bytes) -> bool:
    """Recognize a deliberately small source grammar without executing any SQL.

    Table/index definitions, ADD COLUMN and counter-maintenance triggers are source.
    The only top-level row permitted is an integer version in a key/value schema
    metadata table declared by the same payload. Ordinary inserts/exports refuse.
    """
    if not raw or len(raw) > MAX_SOURCE_BYTES or b"\0" in raw:
        return False
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    text = SQL_TOKENS.sub(lambda match: " " if match[0].startswith(("--", "/*")) else match[0], text)
    statements, buffer = [], ""
    for char in text:
        buffer += char
        if char == ";" and sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    if buffer.strip() or not statements or len(statements) > 512:
        return False
    markers, marker_rows = set(), set()
    for statement in statements:
        metadata = re.fullmatch(rf"CREATE\s+TABLE\s+({IDENTIFIER})\s*\(\s*key\s+TEXT\s+PRIMARY\s+KEY\s*,\s*value\s+TEXT\s+NOT\s+NULL\s*\)\s*;", statement, re.I)
        if metadata:
            markers.add(metadata[1].lower())
    trigger = re.compile(
        rf"CREATE\s+TRIGGER\s+{IDENTIFIER}\s+AFTER\s+UPDATE\s+OF\s+{IDENTIFIER}\s+ON\s+(?P<table>{IDENTIFIER})\s+FOR\s+EACH\s+ROW\s+WHEN\s+NEW\.(?P<counter>{IDENTIFIER})\s*=\s*OLD\.(?P=counter)\s+BEGIN\s+UPDATE\s+(?P=table)\s+SET\s+(?P=counter)\s*=\s*OLD\.(?P=counter)\s*\+\s*1\s+WHERE\s+(?P<key>{IDENTIFIER})\s*=\s*NEW\.(?P=key)\s*;\s*END\s*;", re.I)
    changed_column_trigger = re.compile(
        rf"CREATE\s+TRIGGER\s+{IDENTIFIER}\s+AFTER\s+UPDATE\s+OF\s+(?P<watched>{IDENTIFIER})\s+ON\s+(?P<table>{IDENTIFIER})\s+(?:FOR\s+EACH\s+ROW\s+)?WHEN\s*\(\s*OLD\.(?P=watched)\s+IS\s+NOT\s+NEW\.(?P=watched)\s*\)\s+BEGIN\s+UPDATE\s+(?P=table)\s+SET\s+(?P<counter>{IDENTIFIER})\s*=\s*(?P=counter)\s*\+\s*1\s+WHERE\s+(?P<key>{IDENTIFIER})\s*=\s*NEW\.(?P=key)\s*;\s*END\s*;", re.I)
    for statement in statements:
        unquoted = SQL_TOKENS.sub(lambda match: " " if match[0].startswith(("'", '"')) else match[0], statement)
        if re.search(r"\bAS\s+(?:SELECT|WITH)\b", unquoted, re.I):
            return False
        if re.fullmatch(rf"CREATE\s+TABLE\s+{IDENTIFIER}\s*\([\s\S]+\)\s*;", statement, re.I):
            continue
        if re.fullmatch(rf"CREATE\s+(?:UNIQUE\s+)?INDEX\s+{IDENTIFIER}\s+ON\s+{IDENTIFIER}\s*\([\s\S]+\)\s*(?:WHERE\s+{IDENTIFIER}\s+LIKE\s+'(?:''|[^'])*'\s*)?;", statement, re.I):
            continue
        if re.fullmatch(rf"ALTER\s+TABLE\s+{IDENTIFIER}\s+ADD\s+COLUMN\s+{IDENTIFIER}\s+[^;]+;", statement, re.I):
            continue
        if trigger.fullmatch(statement) or changed_column_trigger.fullmatch(statement):
            continue
        marker = re.fullmatch(rf"INSERT\s+INTO\s+({IDENTIFIER})\s*\(\s*key\s*,\s*value\s*\)\s*VALUES\s*\(\s*'version'\s*,\s*'([0-9]{{1,9}})'\s*\)\s*;", statement, re.I)
        if marker and marker[1].lower() in markers and marker[1].lower() not in marker_rows:
            marker_rows.add(marker[1].lower())
            continue
        return False
    return True


def source_constant(raw: bytes, name: str) -> bytes | None:
    if not raw or len(raw) > MAX_SOURCE_BYTES or b"\0" in raw:
        return None
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    # A fixture consists only of line comments/whitespace and one exported raw
    # string constant. A match inside comments, another string, a disabled cfg or
    # an ambiguous second declaration is not a compiled source successor.
    trivia = r"(?:(?://[^\n]*(?:\n|\Z))|\s)*"
    pattern = re.compile(trivia + r"pub\s+const\s+" + re.escape(name) + r'\s*:\s*&str\s*=\s*r(?P<hashes>\#{1,8})"(?P<body>(?:(?!"(?P=hashes))[\s\S])*)"(?P=hashes)\s*;' + trivia)
    match = pattern.fullmatch(text)
    return match["body"].encode() if match else None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)


def _blob(root: Path, revision: str, path: str) -> bytes | None:
    result = _git(root, "ls-tree", "-z", revision, "--", path)
    if result.returncode:
        raise ValueError("schema-history-tree-unavailable")
    rows = [row for row in result.stdout.split(b"\0") if row]
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("schema-history-source-ambiguous")
    metadata, actual = rows[0].split(b"\t", 1)
    mode, kind, oid = metadata.split()
    if mode not in {b"100644", b"100755"} or kind != b"blob" or actual.decode() != path:
        raise ValueError("schema-history-source-not-regular")
    size = _git(root, "cat-file", "-s", oid.decode())
    if size.returncode or not size.stdout.strip().isdigit() or not 0 < int(size.stdout) <= MAX_SOURCE_BYTES:
        raise ValueError("schema-history-source-unavailable")
    content = _git(root, "cat-file", "blob", oid.decode())
    if content.returncode or len(content.stdout) != int(size.stdout):
        raise ValueError("schema-history-source-unavailable")
    return content.stdout


def verify_context(root: Path, reference: str, declarations: tuple[SchemaHistoryDeclaration, ...]) -> tuple[dict[tuple[str, str], SchemaHistoryDeclaration], list[Finding]]:
    """Bind proof to the selected commit/range endpoint, never an arbitrary worktree."""
    if not declarations:
        return {}, []
    right = reference.rsplit("..", 1)[-1] or "HEAD"
    if right.startswith("-") or any(char.isspace() for char in right):
        return {}, [Finding("error", "schema-history-candidate-unavailable", "Reviewed schema history requires a unique selected candidate commit.", evidence_class="schema-source-history")]
    resolved = _git(root, "rev-parse", "--verify", "--end-of-options", right + "^{commit}")
    if resolved.returncode:
        return {}, [Finding("error", "schema-history-candidate-unavailable", "Unable to resolve the selected schema-history candidate.", evidence_class="schema-source-history")]
    candidate = resolved.stdout.decode().strip()
    verified, failures = {}, []
    for declaration in declarations:
        try:
            if _blob(root, candidate, declaration.path) is not None:
                raise ValueError("schema-history-predecessor-still-current")
            ancestor = _git(root, "merge-base", "--is-ancestor", declaration.producer_revision, candidate)
            if ancestor.returncode != 0 or _blob(root, declaration.producer_revision, declaration.producer_path) is None:
                raise ValueError("schema-history-producer-unavailable")
            successor = _blob(root, candidate, declaration.successor)
            payload = source_constant(successor or b"", declaration.constant)
            if payload is None or hashlib.sha256(payload).hexdigest() != declaration.sha256 or not schema_only(payload):
                raise ValueError("schema-history-successor-unverified")
            verified[(declaration.path, declaration.sha256)] = declaration
        except (OSError, ValueError, UnicodeError):
            failures.append(Finding("error", "schema-history-proof-unavailable", "The declared historical schema lacks complete committed provenance and byte-identical bounded source-successor proof.", path=declaration.path, evidence_class="schema-source-history"))
    return verified, failures
