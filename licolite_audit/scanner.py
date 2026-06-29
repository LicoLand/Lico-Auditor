from __future__ import annotations

import subprocess
from io import BytesIO
from pathlib import Path

from .models import Finding
from .privacy_rules import RULES, iter_text_files, should_scan_file, value_fingerprint


def line_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    column = index + 1 if previous_newline == -1 else index - previous_newline
    return line, column


def scan_text(relative_path: str, text: str, *, commit: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(0)
            if "<" in value and ">" in value and rule.rule_id != "operational-endpoint-url":
                continue
            if rule.should_report is not None and not rule.should_report(value, relative_path):
                continue
            line, column = line_column(text, match.start())
            findings.append(
                Finding(
                    severity=rule.severity,
                    rule=rule.rule_id,
                    message=rule.message,
                    path=relative_path,
                    line=line,
                    column=column,
                    fingerprint=value_fingerprint(value),
                    evidence_class=rule.evidence_class,
                    commit=commit,
                )
            )
    return findings


def scan_worktree(repo_root: Path, *, commit: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_text_files(repo_root):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw:
            continue
        text = raw.decode("utf-8", "replace")
        relative_path = path.relative_to(repo_root).as_posix()
        findings.extend(scan_text(relative_path, text, commit=commit))
    return sorted(findings, key=lambda item: (item.path, item.line, item.column, item.rule))


def git(repo_root: Path, args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _commit_blobs(repo_root: Path, commit: str) -> tuple[list[tuple[bytes, str]], Finding | None]:
    tree = git(repo_root, ["ls-tree", "-rz", commit])
    if tree.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-tree-unavailable",
            message=tree.stderr.decode("utf-8", "replace").strip() or "Unable to enumerate commit tree.",
            commit=commit,
        )
    blobs: list[tuple[bytes, str]] = []
    for entry in tree.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            meta, raw_path = entry.split(b"\t", 1)
            mode, kind, oid = meta.split()
        except ValueError:
            continue
        if kind != b"blob":
            continue
        relative_path = raw_path.decode("utf-8", "replace")
        if should_scan_file(Path(relative_path)):
            blobs.append((oid, relative_path))
    return blobs, None


def _cat_blob_batch(repo_root: Path, blobs: list[tuple[bytes, str]]) -> list[tuple[str, bytes]]:
    if not blobs:
        return []
    request = b"".join(oid + b"\n" for oid, _path in blobs)
    result = git(repo_root, ["cat-file", "--batch"], input_bytes=request)
    if result.returncode != 0:
        return []
    stream = BytesIO(result.stdout)
    contents: list[tuple[str, bytes]] = []
    for _oid, relative_path in blobs:
        header = stream.readline()
        if not header:
            break
        parts = header.rstrip(b"\n").split()
        if len(parts) < 3 or parts[1] != b"blob":
            break
        try:
            size = int(parts[2])
        except ValueError:
            break
        data = stream.read(size)
        stream.read(1)
        contents.append((relative_path, data))
    return contents


def scan_history(repo_root: Path, *, ref: str = "HEAD", max_commits: int = 0) -> list[Finding]:
    revs = git(repo_root, ["rev-list", "--reverse", ref])
    if revs.returncode != 0:
        return [
            Finding(
                severity="error",
                rule="git-history-unavailable",
                message=revs.stderr.decode("utf-8", "replace").strip() or f"Unable to enumerate history for {ref}.",
            )
        ]
    commits = [line for line in revs.stdout.decode("utf-8").splitlines() if line]
    if max_commits > 0:
        commits = commits[-max_commits:]
    findings: list[Finding] = []
    seen_blobs: set[tuple[bytes, str]] = set()
    for commit in commits:
        blobs, tree_error = _commit_blobs(repo_root, commit)
        if tree_error is not None:
            findings.append(tree_error)
            continue
        new_blobs: list[tuple[bytes, str]] = []
        for blob in blobs:
            if blob in seen_blobs:
                continue
            seen_blobs.add(blob)
            new_blobs.append(blob)
        for relative_path, raw in _cat_blob_batch(repo_root, new_blobs):
            if b"\0" in raw:
                continue
            text = raw.decode("utf-8", "replace")
            findings.extend(scan_text(relative_path, text, commit=commit))
    return sorted(findings, key=lambda item: (item.commit, item.path, item.line, item.column, item.rule))


def remote_pull_refs(remote_url: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-remote", remote_url, "refs/pull/*/head"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", "replace").strip() or "Unable to query remote pull refs.")
    return [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
