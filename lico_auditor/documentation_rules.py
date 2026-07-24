from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from .models import Finding


GOVERNED_DOCUMENTATION_PROFILES = frozenset(
    {"meshrix", "licoup", "badtower", "fabrigent"}
)

REQUIRED_PUBLIC_PATHS = (
    "README.md",
    "README.zh-CN.md",
    "PRODUCT.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "LICENSE",
    "SECURITY.md",
    "docs/README.md",
    "docs/RUNBOOK.md",
    "docs/COMPATIBILITY.md",
    "docs/ENTITY-CONFIG-LAYOUT.md",
    "docs/adrs/README.md",
)

REQUIRED_DOCUMENTATION_SECTIONS = (
    "docs/architecture/",
    "docs/functionality/",
    "docs/protocols/",
    "docs/examples/",
)

FORMAL_DOCUMENTATION_PREFIXES = (
    "docs/architecture/",
    "docs/functionality/",
    "docs/protocols/",
    "docs/examples/",
    "docs/adrs/",
)

FORMAL_DOCUMENTATION_FILES = frozenset(
    {
        "docs/README.md",
        "docs/RUNBOOK.md",
        "docs/COMPATIBILITY.md",
        "docs/ENTITY-CONFIG-LAYOUT.md",
    }
)


def is_localized_formal_document(path: str) -> bool:
    """Localized siblings of formal root documents (for example
    docs/COMPATIBILITY.zh-CN.md) carry the same governance as their normative
    source and may live next to it."""
    return any(
        formal.endswith(".md") and path == f"{formal[:-3]}.zh-CN.md"
        for formal in FORMAL_DOCUMENTATION_FILES
    )

LOCAL_ONLY_PREFIXES = (
    "docs/plans/",
    "docs/reports/",
    "cache/",
    "build/",
)

REQUIRED_IGNORED_SENTINELS = (
    "docs/plans/.lico-auditor-sentinel",
    "docs/reports/.lico-auditor-sentinel",
    "cache/.lico-auditor-sentinel",
    "build/.lico-auditor-sentinel",
)

MODULE_MANIFEST_PATTERN = re.compile(
    r"^(?:(apps|packages|crates|modules)/([^/]+)/(?:package\.json|pyproject\.toml|Cargo\.toml|pubspec\.yaml|module\.json)"
    r"|(?:(plugins)/([^/]+)/(?:plugin\.json)))$"
)

MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_LINK_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
GENERATED_MARKER_PATTERN = re.compile(
    r"(?:<!--\s*generated(?:\s+projection)?\s*-->|^generated\s*:\s*(?:true|yes)\s*$)",
    re.IGNORECASE | re.MULTILINE,
)
GENERATED_SOURCE_PATTERN = re.compile(r"(?:generated from|projection source|生成来源)", re.IGNORECASE)
GENERATED_UPDATE_PATTERN = re.compile(r"(?:regenerate|update (?:command|process)|更新方式|重新生成)", re.IGNORECASE)


def _git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _tracked_paths(repo_root: Path) -> set[str] | None:
    result = _git(repo_root, ["ls-files", "-z", "--cached"])
    if result.returncode != 0:
        return None
    return {
        item.decode("utf-8", "replace").replace("\\", "/")
        for item in result.stdout.split(b"\0")
        if item
    }


def _tracked_blob(repo_root: Path, relative_path: str) -> str | None:
    result = _git(repo_root, ["show", f":{relative_path}"])
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace")


def _is_git_worktree(repo_root: Path) -> bool:
    result = _git(repo_root, ["rev-parse", "--is-inside-work-tree"])
    return result.returncode == 0 and result.stdout.strip() == b"true"


def _is_ignored(repo_root: Path, relative_path: str) -> bool:
    result = _git(repo_root, ["check-ignore", "--no-index", "--quiet", "--", relative_path])
    return result.returncode == 0


def _finding(rule: str, path: str, message: str, *, severity: str = "high-risk") -> Finding:
    return Finding(
        severity=severity,
        rule=rule,
        message=message,
        path=path,
        evidence_class="documentation-governance",
    )


def _local_markdown_target(source_path: str, raw_target: str) -> str | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    else:
        target = target.split(maxsplit=1)[0]
    if not target or target.startswith("#") or target.startswith("//") or EXTERNAL_LINK_PATTERN.match(target):
        return None
    target = unquote(target.split("#", 1)[0].split("?", 1)[0]).strip()
    if not target:
        return None
    source_parent = PurePosixPath(source_path).parent
    parts: list[str] = []
    for part in (source_parent / target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _markdown_targets(source_path: str, text: str) -> set[str]:
    targets: set[str] = set()
    for match in MARKDOWN_LINK_PATTERN.finditer(text):
        target = _local_markdown_target(source_path, match.group(1))
        if target is not None:
            targets.add(target)
    return targets


def documentation_governance_findings(repo_root: Path, profile: str) -> list[Finding]:
    if profile not in GOVERNED_DOCUMENTATION_PROFILES or not _is_git_worktree(repo_root):
        return []

    tracked = _tracked_paths(repo_root)
    if tracked is None:
        return [
            _finding(
                "documentation-git-state-unavailable",
                "<repository>",
                "Unable to inspect the tracked publication candidate.",
                severity="error",
            )
        ]

    findings: list[Finding] = []

    for path in REQUIRED_PUBLIC_PATHS:
        if path not in tracked:
            findings.append(
                _finding(
                    "documentation-required-path-missing",
                    path,
                    "A required public documentation entry point is missing from the tracked candidate.",
                )
            )

    for prefix in REQUIRED_DOCUMENTATION_SECTIONS:
        if not any(path.startswith(prefix) and path.lower().endswith(".md") for path in tracked):
            findings.append(
                _finding(
                    "documentation-required-section-missing",
                    prefix,
                    "A required formal documentation section has no tracked Markdown document.",
                )
            )

    for path in sorted(tracked):
        if any(path.startswith(prefix) for prefix in LOCAL_ONLY_PREFIXES):
            findings.append(
                _finding(
                    "documentation-local-asset-tracked",
                    path,
                    "Local-only plans, reports, caches, and build outputs must not be tracked.",
                )
            )
        if path.startswith(("skills/", ".agents/skills/", ".codex/skills/")) and Path(path).name == "SKILL.md":
            findings.append(
                _finding(
                    "documentation-external-skill-tracked",
                    path,
                    "Project agent skills must be maintained and published by the external skill repository.",
                )
            )
        if path.startswith("docs/") and path.lower().endswith(".md"):
            if (
                path not in FORMAL_DOCUMENTATION_FILES
                and not is_localized_formal_document(path)
                and not path.startswith(FORMAL_DOCUMENTATION_PREFIXES)
            ):
                findings.append(
                    _finding(
                        "documentation-formal-path-invalid",
                        path,
                        "Formal project Markdown must use an approved documentation category.",
                    )
                )

    for sentinel in REQUIRED_IGNORED_SENTINELS:
        if not _is_ignored(repo_root, sentinel):
            findings.append(
                _finding(
                    "documentation-local-asset-not-ignored",
                    str(PurePosixPath(sentinel).parent) + "/",
                    "The local-only asset directory must be ignored by the repository.",
                )
            )

    module_roots = {
        "/".join(part for part in match.groups() if part is not None)
        for path in tracked
        if (match := MODULE_MANIFEST_PATTERN.fullmatch(path)) is not None
    }
    for module_root in sorted(module_roots):
        readme_path = f"{module_root}/README.md"
        if readme_path not in tracked:
            findings.append(
                _finding(
                    "documentation-module-readme-missing",
                    readme_path,
                    "An independently maintained module must provide a tracked lightweight README.",
                )
            )

    if "README.md" in tracked and "README.zh-CN.md" in tracked:
        readme = _tracked_blob(repo_root, "README.md")
        localized = _tracked_blob(repo_root, "README.zh-CN.md")
        if readme is not None and localized is not None:
            if "README.zh-CN.md" not in readme:
                findings.append(
                    _finding(
                        "documentation-readme-language-link-missing",
                        "README.md",
                        "The normative README must link to the Simplified Chinese localization.",
                    )
                )
            if "README.md" not in localized:
                findings.append(
                    _finding(
                        "documentation-readme-language-link-missing",
                        "README.zh-CN.md",
                        "The localized README must link to the normative README.",
                    )
                )
            combined = f"{readme}\n{localized}"
            has_normative_role = re.search(r"(?:normative language|规范语言)", combined, re.IGNORECASE)
            has_localized_role = re.search(
                r"(?:localized language|localization|本地化(?:语言|版本))",
                combined,
                re.IGNORECASE,
            )
            if not has_normative_role or not has_localized_role:
                findings.append(
                    _finding(
                        "documentation-readme-language-role-missing",
                        "README.md",
                        "The README pair must identify the normative and localized languages.",
                    )
                )

    markdown_text: dict[str, str] = {}
    for path in sorted(path for path in tracked if path.lower().endswith(".md")):
        content = _tracked_blob(repo_root, path)
        if content is None:
            findings.append(
                _finding(
                    "documentation-tracked-file-unavailable",
                    path,
                    "A tracked Markdown file cannot be inspected.",
                    severity="error",
                )
            )
        else:
            markdown_text[path] = content

    for source_path, text in markdown_text.items():
        for target in sorted(_markdown_targets(source_path, text)):
            if target not in tracked and not any(path.startswith(f"{target.rstrip('/')}/") for path in tracked):
                findings.append(
                    _finding(
                        "documentation-link-target-missing",
                        source_path,
                        "A local Markdown link does not resolve inside the tracked candidate.",
                    )
                )

    if "docs/README.md" in markdown_text:
        indexed = _markdown_targets("docs/README.md", markdown_text["docs/README.md"])
        formal_documents = {
            path
            for path in tracked
            if path.lower().endswith(".md")
            and path != "docs/README.md"
            and (path in FORMAL_DOCUMENTATION_FILES or path.startswith(FORMAL_DOCUMENTATION_PREFIXES))
        }
        for path in sorted(formal_documents - indexed):
            findings.append(
                _finding(
                    "documentation-index-entry-missing",
                    path,
                    "The formal document is not linked from docs/README.md.",
                )
            )

    for path, text in markdown_text.items():
        if not (path.endswith(".generated.md") or GENERATED_MARKER_PATTERN.search(text)):
            continue
        if not GENERATED_SOURCE_PATTERN.search(text):
            findings.append(
                _finding(
                    "documentation-generated-source-missing",
                    path,
                    "A generated documentation projection must identify its canonical source.",
                )
            )
        if not GENERATED_UPDATE_PATTERN.search(text):
            findings.append(
                _finding(
                    "documentation-generated-update-missing",
                    path,
                    "A generated documentation projection must identify its update process.",
                )
            )

    return sorted(findings, key=lambda item: (item.path, item.rule))
