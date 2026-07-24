from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path

from .models import Finding
from .privacy_rules import value_fingerprint


CURSOR_IDENTITY_PATTERN = re.compile(
    r"(?i)(?<![a-z0-9])cursor(?:ai|bot|agent|[\s_.-]+(?:ai|bot|agent))?(?![a-z0-9])"
)
COMMIT_TRAILER_PATTERN = re.compile(
    r"(?im)^(?:co-authored-by|signed-off-by|authored-by|committed-by|"
    r"generated-by|assisted-by|made-with)\s*:[^\r\n]*"
)
CONTRIBUTOR_FIELD_PATTERN = re.compile(
    r"(?i)\b(?:authors?|contributors?|maintainers?|developers?|credits?)\b\s*[\"']?\s*[:=]"
)
MARKDOWN_CONTRIBUTOR_HEADING_PATTERN = re.compile(
    r"(?im)^#{1,6}\s+(?:authors?|contributors?|maintainers?|credits?)\s*$"
)
CONTRIBUTOR_FILE_NAMES = frozenset(
    {
        ".all-contributorsrc",
        ".mailmap",
        "authors",
        "authors.md",
        "authors.txt",
        "contributors",
        "contributors.md",
        "contributors.txt",
    }
)
PROJECT_METADATA_FILE_NAMES = frozenset(
    {
        "cargo.toml",
        "citation.cff",
        "composer.json",
        "package.json",
        "pom.xml",
        "pubspec.yaml",
        "pyproject.toml",
    }
)
CODEX_BRANCH_PREFIXES = ("codex/", "codex-", "codex_")


def _line_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    column = index + 1 if previous_newline == -1 else index - previous_newline
    return line, column


def _cursor_matches_contributor_context(relative_path: str, text: str, start: int) -> bool:
    file_name = Path(relative_path).name.casefold()
    if file_name in CONTRIBUTOR_FILE_NAMES:
        return True

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    if COMMIT_TRAILER_PATTERN.match(line) is not None:
        return True

    prefix = text[max(0, start - 1024) : start]
    if file_name in PROJECT_METADATA_FILE_NAMES:
        field = list(CONTRIBUTOR_FIELD_PATTERN.finditer(prefix))
        if field and start - (max(0, start - 1024) + field[-1].end()) <= 512:
            return True

    heading = list(MARKDOWN_CONTRIBUTOR_HEADING_PATTERN.finditer(prefix))
    if not heading:
        return False
    heading_end = max(0, start - 1024) + heading[-1].end()
    intervening = text[heading_end:start]
    return re.search(r"(?m)^#{1,6}\s+", intervening) is None


def scan_contributor_attribution(
    relative_path: str,
    text: str,
    *,
    commit: str = "",
) -> list[Finding]:
    findings: list[Finding] = []
    for match in CURSOR_IDENTITY_PATTERN.finditer(text):
        if not _cursor_matches_contributor_context(relative_path, text, match.start()):
            continue
        line, column = _line_column(text, match.start())
        findings.append(
            Finding(
                severity="high-risk",
                rule="cursor-contributor-attribution",
                message="Cursor must not be listed as a project author, maintainer, or contributor.",
                path=relative_path,
                line=line,
                column=column,
                fingerprint=value_fingerprint(match.group(0)),
                evidence_class="contributor-metadata",
                commit=commit,
            )
        )
    return findings


def _git(repo_root: Path, args: list[str], *, input_bytes: bytes | None = None):
    import subprocess

    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _commit_ids(
    repo_root: Path,
    ref: str,
    *,
    include_history: bool,
    max_commits: int,
) -> tuple[list[str], Finding | None]:
    args = ["rev-list", "--reverse", ref] if include_history else ["rev-parse", "--verify", f"{ref}^{{commit}}"]
    result = _git(repo_root, args)
    if result.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-contribution-state-unavailable",
            message="Unable to inspect commit attribution metadata.",
            fingerprint=value_fingerprint(result.stderr.decode("utf-8", "replace")),
            evidence_class="git-commit-metadata",
        )
    commits = [line for line in result.stdout.decode("ascii", "replace").splitlines() if line]
    if include_history and max_commits > 0:
        commits = commits[-max_commits:]
    return commits, None


def _commit_objects(repo_root: Path, commits: list[str]) -> tuple[list[tuple[str, bytes]], Finding | None]:
    if not commits:
        return [], None
    result = _git(
        repo_root,
        ["cat-file", "--batch"],
        input_bytes=b"".join(commit.encode("ascii") + b"\n" for commit in commits),
    )
    if result.returncode != 0:
        return [], Finding(
            severity="error",
            rule="git-contribution-state-unavailable",
            message="Unable to inspect commit attribution metadata.",
            fingerprint=value_fingerprint(result.stderr.decode("utf-8", "replace")),
            evidence_class="git-commit-metadata",
        )

    stream = BytesIO(result.stdout)
    objects: list[tuple[str, bytes]] = []
    for commit in commits:
        header = stream.readline().rstrip(b"\n").split()
        if len(header) < 3 or header[1] != b"commit":
            return [], Finding(
                severity="error",
                rule="git-contribution-state-unavailable",
                message="Unable to inspect commit attribution metadata.",
                fingerprint=value_fingerprint(commit),
                evidence_class="git-commit-metadata",
            )
        try:
            size = int(header[2])
        except ValueError:
            return [], Finding(
                severity="error",
                rule="git-contribution-state-unavailable",
                message="Unable to inspect commit attribution metadata.",
                fingerprint=value_fingerprint(commit),
                evidence_class="git-commit-metadata",
            )
        raw = stream.read(size)
        stream.read(1)
        objects.append((commit, raw))
    return objects, None


def _scan_commit_object(commit: str, raw: bytes) -> list[Finding]:
    text = raw.decode("utf-8", "replace")
    header, _separator, message = text.partition("\n\n")
    candidates: list[str] = [
        line
        for line in header.splitlines()
        if line.startswith(("author ", "committer "))
    ]
    candidates.extend(match.group(0) for match in COMMIT_TRAILER_PATTERN.finditer(message))

    findings: list[Finding] = []
    for candidate in candidates:
        identity = CURSOR_IDENTITY_PATTERN.search(candidate)
        if identity is None:
            continue
        findings.append(
            Finding(
                severity="high-risk",
                rule="cursor-commit-attribution",
                message="Cursor must not appear in commit author, committer, or attribution trailer metadata.",
                path="<commit-metadata>",
                fingerprint=value_fingerprint(identity.group(0)),
                evidence_class="git-commit-metadata",
                commit=commit,
            )
        )
    return findings


def _has_codex_prefix(branch_name: str) -> bool:
    normalized = branch_name.casefold()
    return normalized == "codex" or normalized.startswith(CODEX_BRANCH_PREFIXES)


def _scan_branch_refs(repo_root: Path) -> list[Finding]:
    result = _git(
        repo_root,
        ["for-each-ref", "--format=%(refname)", "refs/heads"],
    )
    if result.returncode != 0:
        return [
            Finding(
                severity="error",
                rule="git-contribution-state-unavailable",
                message="Unable to inspect repository branch naming metadata.",
                fingerprint=value_fingerprint(result.stderr.decode("utf-8", "replace")),
                evidence_class="git-branch-metadata",
            )
        ]

    findings: list[Finding] = []
    for ref in result.stdout.decode("utf-8", "replace").splitlines():
        if ref.startswith("refs/heads/"):
            branch_name = ref.removeprefix("refs/heads/")
        else:
            continue
        if not _has_codex_prefix(branch_name):
            continue
        findings.append(
            Finding(
                severity="high-risk",
                rule="codex-prefixed-branch",
                message="Temporary branches must use a meaningful prefix such as feature/ or fix/, not codex.",
                path="<branch-ref>",
                fingerprint=value_fingerprint(ref),
                evidence_class="git-branch-metadata",
            )
        )
    return findings


def scan_git_contribution_governance(
    repo_root: Path,
    *,
    ref: str = "HEAD",
    include_history: bool = False,
    max_commits: int = 0,
) -> list[Finding]:
    findings = _scan_branch_refs(repo_root)
    commits, commit_error = _commit_ids(
        repo_root,
        ref,
        include_history=include_history,
        max_commits=max_commits,
    )
    if commit_error is not None:
        findings.append(commit_error)
        return findings

    objects, object_error = _commit_objects(repo_root, commits)
    if object_error is not None:
        findings.append(object_error)
        return findings
    for commit, raw in objects:
        findings.extend(_scan_commit_object(commit, raw))
    return findings
