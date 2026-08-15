from __future__ import annotations

import json
import subprocess
import re
from dataclasses import replace
from io import BytesIO
from pathlib import Path

from .contribution_rules import scan_contributor_attribution
from .documentation_rules import documentation_governance_findings
from .models import BLOCKING_SEVERITIES, Finding
from .privacy_rules import (
    RULES,
    RepositoryPolicy,
    effective_text_rule_severity,
    file_policy_violations,
    historical_skills_template_successor_path,
    host_from_endpoint,
    is_declared_public_reference_host,
    is_verified_historical_template_successor,
    iter_text_files,
    load_repository_policy,
    looks_like_user_record_collection,
    normalized_repo_path,
    policy_profile_for_repo_name,
    should_scan_text_rule,
    should_scan_file,
    value_fingerprint,
)


SVG_PATH_DATA_ATTR_PATTERN = re.compile(r"""(?is)\bd\s*=\s*(["'])(.*?)\1""")
SVG_PATH_DATA_SUFFIXES = {".html", ".svg", ".tsx", ".vue"}


def line_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    column = index + 1 if previous_newline == -1 else index - previous_newline
    return line, column


def mask_svg_path_data(relative_path: str, text: str) -> str:
    if Path(relative_path).suffix.lower() not in SVG_PATH_DATA_SUFFIXES:
        return text

    def mask(match: re.Match[str]) -> str:
        raw = match.group(0)
        value_start = match.start(2) - match.start(0)
        value_end = match.end(2) - match.start(0)
        return f"{raw[:value_start]}{' ' * (value_end - value_start)}{raw[value_end:]}"

    return SVG_PATH_DATA_ATTR_PATTERN.sub(mask, text)


def scan_text(
    relative_path: str,
    text: str,
    *,
    commit: str = "",
    profile: str | None = None,
    repository_policy: RepositoryPolicy | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    svg_path_masked_text: str | None = None
    for rule in RULES:
        if not should_scan_text_rule(rule.rule_id, relative_path):
            continue
        scan_source = text
        if rule.rule_id == "ip-literal":
            if svg_path_masked_text is None:
                svg_path_masked_text = mask_svg_path_data(relative_path, text)
            scan_source = svg_path_masked_text
        severity = effective_text_rule_severity(rule.rule_id, relative_path)
        for match in rule.pattern.finditer(scan_source):
            value = match.group(0)
            if "<" in value and ">" in value and rule.rule_id != "operational-endpoint-url":
                continue
            if rule.should_report is not None and not rule.should_report(value, relative_path):
                continue
            if (
                rule.rule_id == "disallowed-domain"
                and is_declared_public_reference_host(
                    host_from_endpoint(value),
                    relative_path,
                    repository_policy,
                )
            ):
                continue
            line, column = line_column(text, match.start())
            findings.append(
                Finding(
                    severity=severity,
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


def resolve_scan_profile(repo_root: Path, profile: str | None = None) -> str:
    if profile and profile != "auto":
        return profile
    return policy_profile_for_repo_name(repo_root.name)


def scan_file_policy(
    relative_path: str,
    raw: bytes,
    *,
    commit: str = "",
    profile: str | None = None,
    repository_policy: RepositoryPolicy | None = None,
) -> list[Finding]:
    return [
        Finding(
            severity="high-risk",
            rule=rule,
            message=message,
            path=relative_path,
            fingerprint=fingerprint,
            evidence_class=evidence_class,
            commit=commit,
        )
        for rule, message, evidence_class, fingerprint in file_policy_violations(
            relative_path,
            raw,
            profile,
            repository_policy,
        )
    ]


def scan_worktree(repo_root: Path, *, commit: str = "", profile: str | None = None) -> list[Finding]:
    scan_profile = resolve_scan_profile(repo_root, profile)
    repository_policy, policy_error = load_repository_policy(repo_root, scan_profile)
    findings: list[Finding] = []
    if policy_error is not None:
        findings.append(
            Finding(
                severity="high-risk",
                rule="repository-policy-invalid",
                message=policy_error,
                path=".lico-auditor/policy.json",
                evidence_class="repository-policy",
                commit=commit,
            )
        )
    for path in iter_text_files(repo_root, scan_profile):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        relative_path = path.relative_to(repo_root).as_posix()
        findings.extend(
            scan_file_policy(
                relative_path,
                raw,
                commit=commit,
                profile=scan_profile,
                repository_policy=repository_policy,
            )
        )
        if b"\0" in raw:
            continue
        text = raw.decode("utf-8", "replace")
        findings.extend(
            scan_text(
                relative_path,
                text,
                commit=commit,
                profile=scan_profile,
                repository_policy=repository_policy,
            )
        )
        findings.extend(scan_contributor_attribution(relative_path, text, commit=commit))
    findings.extend(documentation_governance_findings(repo_root, scan_profile))
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


def _commit_blobs(repo_root: Path, commit: str, *, profile: str | None = None) -> tuple[list[tuple[bytes, str]], Finding | None]:
    tree = git(repo_root, ["ls-tree", "-rz", commit])
    if tree.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-tree-unavailable",
            message="Unable to enumerate the requested commit tree.",
            fingerprint=value_fingerprint(tree.stderr.decode("utf-8", "replace")),
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
        if should_scan_file(Path(relative_path), profile):
            blobs.append((oid, relative_path))
    return blobs, None


def _commit_changed_blobs(
    repo_root: Path,
    commit: str,
    *,
    profile: str | None = None,
) -> tuple[list[tuple[bytes, str]], Finding | None]:
    parent = git(repo_root, ["rev-parse", "--verify", f"{commit}^"])
    if parent.returncode != 0:
        return _commit_blobs(repo_root, commit, profile=profile)
    diff = git(
        repo_root,
        [
            "diff-tree",
            "-r",
            "--no-renames",
            "--name-status",
            "-z",
            parent.stdout.strip().decode("ascii", "replace"),
            commit,
        ],
    )
    if diff.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-history-unavailable",
            message="Unable to enumerate the requested commit diff.",
            fingerprint=value_fingerprint(diff.stderr.decode("utf-8", "replace")),
            commit=commit,
        )
    tokens = [token for token in diff.stdout.split(b"\0") if token]
    paths: list[str] = []
    for index in range(0, len(tokens) - 1, 2):
        status = tokens[index].decode("ascii", "replace")
        raw_path = tokens[index + 1]
        if status[:1] not in {"A", "M", "T"}:
            continue
        relative_path = raw_path.decode("utf-8", "replace")
        if should_scan_file(Path(relative_path), profile):
            paths.append(relative_path)
    if not paths:
        return [], None
    listing = git(repo_root, ["ls-tree", "-rz", commit, "--", *paths])
    if listing.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-tree-unavailable",
            message="Unable to enumerate changed blobs in the requested commit.",
            fingerprint=value_fingerprint(listing.stderr.decode("utf-8", "replace")),
            commit=commit,
        )
    blobs: list[tuple[bytes, str]] = []
    for entry in listing.stdout.split(b"\0"):
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


def _head_template_context(
    repo_root: Path,
    ref: str,
    *,
    profile: str,
) -> tuple[set[str], dict[str, tuple[str, bytes] | None]]:
    blobs, tree_error = _commit_blobs(repo_root, ref, profile=profile)
    if tree_error is not None:
        return set(), {}
    head_paths = {normalized_repo_path(relative_path) for _oid, relative_path in blobs}
    template_blobs: list[tuple[bytes, str]] = []
    for oid, relative_path in blobs:
        normalized = normalized_repo_path(relative_path)
        if (
            normalized.startswith("skills/")
            and "/assets/" in normalized
            and normalized.endswith(".template.json")
        ):
            template_blobs.append((oid, relative_path))
    templates: dict[str, tuple[str, bytes] | None] = {}
    for relative_path, raw in _cat_blob_batch(repo_root, template_blobs):
        normalized = normalized_repo_path(relative_path)
        if normalized in templates:
            templates[normalized] = None
        else:
            templates[normalized] = (relative_path, raw)
    return head_paths, templates


def _is_retired_non_sensitive_json(
    relative_path: str,
    raw: bytes,
    *,
    profile: str,
    head_paths: set[str],
    repository_policy: RepositoryPolicy | None,
) -> bool:
    """Demote historical unallowlisted JSON to a warning when the file no
    longer exists at HEAD and its content contains no hard leak signal."""
    if normalized_repo_path(relative_path) in head_paths or b"\0" in raw:
        return False
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return False
    if looks_like_user_record_collection(data):
        return False
    text = raw.decode("utf-8", "replace")
    if any(
        finding.severity in BLOCKING_SEVERITIES
        for finding in scan_text(
            relative_path,
            text,
            profile=profile,
            repository_policy=repository_policy,
        )
    ):
        return False
    if any(
        finding.severity in BLOCKING_SEVERITIES
        for finding in scan_contributor_attribution(relative_path, text)
    ):
        return False
    return True


def _historical_file_policy_findings(
    relative_path: str,
    raw: bytes,
    *,
    commit: str,
    profile: str,
    head_paths: set[str],
    head_templates: dict[str, tuple[str, bytes] | None],
    repository_policy: RepositoryPolicy | None = None,
) -> list[Finding]:
    policy_findings = scan_file_policy(
        relative_path,
        raw,
        commit=commit,
        profile=profile,
        repository_policy=repository_policy,
    )
    if not any(item.rule == "json-data-file-not-allowlisted" for item in policy_findings):
        return policy_findings
    normalized = normalized_repo_path(relative_path)
    successor_path = historical_skills_template_successor_path(relative_path, profile)
    if successor_path is not None and normalized not in head_paths:
        successor = head_templates.get(normalized_repo_path(successor_path))
        if successor is not None:
            actual_successor_path, successor_raw = successor
            if not scan_file_policy(
                actual_successor_path,
                successor_raw,
                profile=profile,
                repository_policy=repository_policy,
            ) and b"\0" not in successor_raw:
                successor_text = successor_raw.decode("utf-8", "replace")
                if not scan_text(
                    actual_successor_path,
                    successor_text,
                    profile=profile,
                    repository_policy=repository_policy,
                ) and is_verified_historical_template_successor(
                    relative_path,
                    raw,
                    actual_successor_path,
                    successor_raw,
                    profile,
                ):
                    return [
                        item
                        for item in policy_findings
                        if item.rule != "json-data-file-not-allowlisted"
                    ]
    if _is_retired_non_sensitive_json(
        relative_path,
        raw,
        profile=profile,
        head_paths=head_paths,
        repository_policy=repository_policy,
    ):
        return [
            replace(item, severity="warning")
            if item.rule == "json-data-file-not-allowlisted"
            else item
            for item in policy_findings
        ]
    return policy_findings


def scan_history(
    repo_root: Path,
    *,
    ref: str = "HEAD",
    max_commits: int = 0,
    profile: str | None = None,
    full_tree: bool = False,
) -> list[Finding]:
    scan_profile = resolve_scan_profile(repo_root, profile)
    repository_policy, policy_error = load_repository_policy(repo_root, scan_profile)
    revs = git(repo_root, ["rev-list", "--reverse", ref])
    if revs.returncode != 0:
        return [
            Finding(
                severity="error",
                rule="git-history-unavailable",
                message="Unable to enumerate the requested git history.",
                fingerprint=value_fingerprint(revs.stderr.decode("utf-8", "replace")),
            )
        ]
    commits = [line for line in revs.stdout.decode("utf-8").splitlines() if line]
    if max_commits > 0:
        commits = commits[-max_commits:]
    findings: list[Finding] = []
    if policy_error is not None:
        findings.append(
            Finding(
                severity="high-risk",
                rule="repository-policy-invalid",
                message=policy_error,
                path=".lico-auditor/policy.json",
                evidence_class="repository-policy",
            )
        )
    head_paths, head_templates = _head_template_context(repo_root, ref, profile=scan_profile)
    seen_blobs: set[tuple[bytes, str]] = set()
    for commit in commits:
        if full_tree:
            blobs, tree_error = _commit_blobs(repo_root, commit, profile=scan_profile)
        else:
            blobs, tree_error = _commit_changed_blobs(repo_root, commit, profile=scan_profile)
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
            findings.extend(
                _historical_file_policy_findings(
                    relative_path,
                    raw,
                    commit=commit,
                    profile=scan_profile,
                    head_paths=head_paths,
                    head_templates=head_templates,
                    repository_policy=repository_policy,
                )
            )
            if b"\0" in raw:
                continue
            text = raw.decode("utf-8", "replace")
            findings.extend(
                scan_text(
                    relative_path,
                    text,
                    commit=commit,
                    profile=scan_profile,
                    repository_policy=repository_policy,
                )
            )
            findings.extend(scan_contributor_attribution(relative_path, text, commit=commit))
    return sorted(findings, key=lambda item: (item.commit, item.path, item.line, item.column, item.rule))


def remote_pull_refs(remote_url: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-remote", remote_url, "refs/pull/*/head"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to query remote pull refs.")
    return [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
