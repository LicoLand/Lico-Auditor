from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from lico_auditor.scanner import scan_worktree


REQUIRED_CONTENT = {
    "README.md": (
        "# Example\n\nEnglish is the normative language. Simplified Chinese is the localized language.\n\n"
        "[简体中文](README.zh-CN.md)\n"
    ),
    "README.zh-CN.md": (
        "# 示例\n\n英语是规范语言，简体中文是本地化语言。\n\n"
        "[English](README.md)\n"
    ),
    "PRODUCT.md": "# Product\n",
    "CONTRIBUTING.md": "# Contributing\n",
    "CODE_OF_CONDUCT.md": "# Code of Conduct\n",
    "CHANGELOG.md": "# Changelog\n",
    "LICENSE": "Synthetic license fixture.\n",
    "SECURITY.md": "# Security\n",
    "docs/RUNBOOK.md": "# Runbook\n",
    "docs/COMPATIBILITY.md": "# Compatibility\n",
    "docs/ENTITY-CONFIG-LAYOUT.md": "# Entity Config Layout\n",
    "docs/architecture/OVERVIEW.md": "# Architecture\n",
    "docs/functionality/OVERVIEW.md": "# Functionality\n",
    "docs/protocols/OVERVIEW.md": "# Protocols\n",
    "docs/examples/README.md": "# Examples\n",
    "docs/adrs/README.md": "# ADR Index\n",
}


def run_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def create_governed_repository(
    root: Path,
    *,
    omitted: frozenset[str] = frozenset(),
    ignored_directories: tuple[str, ...] = ("docs/plans/", "docs/reports/", "cache/", "build/"),
) -> None:
    files = dict(REQUIRED_CONTENT)
    index_links = [
        path
        for path in files
        if path.startswith("docs/") and path != "docs/README.md"
    ]
    files["docs/README.md"] = "# Documentation\n\n" + "\n".join(
        f"- [{Path(path).stem}]({path.removeprefix('docs/')})" for path in index_links
    )
    files[".gitignore"] = "\n".join(ignored_directories) + "\n"

    for relative_path, content in files.items():
        if relative_path in omitted:
            continue
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    run_git(root, "init", "-q")
    run_git(root, "add", ".")


def rules(findings: list[object]) -> set[str]:
    return {getattr(item, "rule") for item in findings}


class DocumentationGovernanceTests(unittest.TestCase):
    def test_complete_public_document_layout_passes_for_product_profiles(self) -> None:
        for profile in ("licoup", "badtower", "fabrigent"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                create_governed_repository(root)
                self.assertEqual(scan_worktree(root, profile=profile), [])

    def test_other_profiles_do_not_inherit_product_documentation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run_git(root, "init", "-q")
            (root / "README.md").write_text("# Support repository\n", encoding="utf-8")
            run_git(root, "add", "README.md")
            self.assertEqual(scan_worktree(root, profile="common"), [])

    def test_required_public_path_must_be_tracked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root, omitted=frozenset({"SECURITY.md"}))
            findings = scan_worktree(root, profile="fabrigent")
        self.assertIn("documentation-required-path-missing", rules(findings))
        self.assertTrue(any(item.path == "SECURITY.md" for item in findings))

    def test_local_assets_must_be_ignored_and_untracked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(
                root,
                ignored_directories=("docs/plans/", "docs/reports/", "build/"),
            )
            cache_file = root / "cache" / "download.bin"
            cache_file.parent.mkdir()
            cache_file.write_bytes(b"synthetic")
            run_git(root, "add", "-f", "cache/download.bin")
            findings = scan_worktree(root, profile="licoup")
        self.assertIn("documentation-local-asset-not-ignored", rules(findings))
        self.assertIn("documentation-local-asset-tracked", rules(findings))

    def test_manifest_owned_module_does_not_require_readme(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            manifest = root / "packages" / "example" / "package.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"name":"example","version":"1.0.0"}', encoding="utf-8")
            run_git(root, "add", "packages/example/package.json")
            findings = scan_worktree(root, profile="fabrigent")
        self.assertNotIn("documentation-module-readme-missing", rules(findings))

    def test_root_readmes_do_not_require_links_or_language_roles(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            (root / "README.zh-CN.md").write_text("# 示例\n", encoding="utf-8")
            run_git(root, "add", "README.md", "README.zh-CN.md")
            findings = scan_worktree(root, profile="licoup")
        self.assertEqual(findings, [])

    def test_root_readmes_remain_required_public_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(
                root,
                omitted=frozenset({"README.md"}),
            )
            findings = scan_worktree(root, profile="fabrigent")
        missing = [
            item
            for item in findings
            if item.rule == "documentation-required-path-missing"
        ]
        self.assertEqual({item.path for item in missing}, {"README.md"})

    def test_formal_docs_require_approved_path_index_and_valid_links(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            old_doc = root / "docs" / "specs" / "OLD.md"
            old_doc.parent.mkdir()
            old_doc.write_text("# Old\n\n[Missing](missing.md)\n", encoding="utf-8")
            unindexed = root / "docs" / "architecture" / "UNINDEXED.md"
            unindexed.write_text("# Unindexed\n", encoding="utf-8")
            run_git(root, "add", "docs/specs/OLD.md", "docs/architecture/UNINDEXED.md")
            findings = scan_worktree(root, profile="fabrigent")
        self.assertIn("documentation-formal-path-invalid", rules(findings))
        self.assertIn("documentation-link-target-missing", rules(findings))
        self.assertIn("documentation-index-entry-missing", rules(findings))

    def test_governed_release_projection_is_formal_and_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            projection = root / "docs" / "releases" / "README.md"
            projection.parent.mkdir()
            projection.write_text(
                "<!-- Generated by tools/release_governance.py; edit plan.json, not this file. -->\n"
                "# Release status\n",
                encoding="utf-8",
            )
            with (root / "docs" / "README.md").open("a", encoding="utf-8") as index:
                index.write("\n- [Release status](releases/README.md)\n")
            run_git(root, "add", "docs/README.md", "docs/releases/README.md")
            self.assertEqual(scan_worktree(root, profile="fabrigent"), [])

    def test_project_repository_must_not_publish_agent_skill_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            skill = root / "skills" / "copied" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("# Copied skill\n", encoding="utf-8")
            run_git(root, "add", "skills/copied/SKILL.md")
            findings = scan_worktree(root, profile="licoup")
        self.assertIn("documentation-external-skill-tracked", rules(findings))

    def test_generated_projection_declares_source_and_update_process(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            generated = root / "docs" / "architecture" / "MODEL.generated.md"
            generated.write_text("<!-- generated -->\n# Model\n", encoding="utf-8")
            with (root / "docs" / "README.md").open("a", encoding="utf-8") as index:
                index.write("\n- [Generated model](architecture/MODEL.generated.md)\n")
            run_git(root, "add", "docs/README.md", "docs/architecture/MODEL.generated.md")
            findings = scan_worktree(root, profile="fabrigent")
        self.assertIn("documentation-generated-source-missing", rules(findings))
        self.assertIn("documentation-generated-update-missing", rules(findings))

    def test_generated_projection_prose_does_not_mark_a_document_as_generated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            create_governed_repository(root)
            protocol = root / "docs" / "protocols" / "PROJECTION.md"
            protocol.write_text(
                "# Projection\n\nGenerated projections are verified by the protocol tool.\n",
                encoding="utf-8",
            )
            with (root / "docs" / "README.md").open("a", encoding="utf-8") as index:
                index.write("\n- [Projection](protocols/PROJECTION.md)\n")
            run_git(root, "add", "docs/README.md", "docs/protocols/PROJECTION.md")
            findings = scan_worktree(root, profile="badtower")
        self.assertNotIn("documentation-generated-source-missing", rules(findings))
        self.assertNotIn("documentation-generated-update-missing", rules(findings))

    def test_retired_documentation_json_paths_are_not_allowlisted(self) -> None:
        for relative_path in (
            "docs/plan/draft.json",
            "docs/scenarios/example.json",
            "docs/generated/catalog.generated.json",
        ):
            with self.subTest(relative_path=relative_path), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                target = root / relative_path
                target.parent.mkdir(parents=True)
                target.write_text('{"schemaVersion":"1","kind":"example"}', encoding="utf-8")
                findings = scan_worktree(root, profile="fabrigent")
                self.assertIn("json-data-file-not-allowlisted", rules(findings))


if __name__ == "__main__":
    unittest.main()
