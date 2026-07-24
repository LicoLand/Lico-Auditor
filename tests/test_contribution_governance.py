from __future__ import annotations

import os
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from lico_auditor.cli import collect_findings
from lico_auditor.contribution_rules import (
    scan_contributor_attribution,
    scan_git_contribution_governance,
)


class ContributionGovernanceTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "audit@example.test"], cwd=root, check=True)

    def commit(self, root: Path, message: str, *, author_name: str = "Audit Test") -> None:
        (root / "tracked.txt").write_text(message, encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": author_name,
                "GIT_AUTHOR_EMAIL": "author@example.test",
            }
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", message],
            cwd=root,
            check=True,
            env=environment,
        )

    def test_cursor_in_contributors_file_is_blocked(self) -> None:
        findings = scan_contributor_attribution("CONTRIBUTORS.md", "- Cursor AI\n")
        self.assertEqual([item.rule for item in findings], ["cursor-contributor-attribution"])

    def test_cursor_in_multiline_project_author_field_is_blocked(self) -> None:
        text = '"contributors": [\n  {"name": "Cursor Bot"}\n]\n'
        findings = scan_contributor_attribution("package.json", text)
        self.assertEqual([item.rule for item in findings], ["cursor-contributor-attribution"])

    def test_ordinary_cursor_documentation_is_allowed(self) -> None:
        text = "Use the Cursor editor when testing this integration."
        self.assertEqual(scan_contributor_attribution("README.md", text), [])

    def test_cursor_commit_author_is_blocked_without_history_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "implement feature", author_name="Cursor Agent")
            findings = collect_findings(root)

        self.assertIn("cursor-commit-attribution", {item.rule for item in findings})

    def test_cursor_commit_trailer_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "implement feature\n\nCo-authored-by: Cursor Bot <bot@example.test>")
            findings = scan_git_contribution_governance(root)

        self.assertEqual(
            [item.rule for item in findings],
            ["cursor-commit-attribution"],
        )

    def test_cursor_made_with_trailer_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "implement feature\n\nMade-with: Cursor")
            findings = scan_git_contribution_governance(root)

        self.assertEqual(
            [item.rule for item in findings],
            ["cursor-commit-attribution"],
        )

    def test_cursor_mention_in_commit_body_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "document Cursor integration")
            findings = scan_git_contribution_governance(root)

        self.assertNotIn("cursor-commit-attribution", {item.rule for item in findings})

    def test_codex_prefixed_local_branch_is_blocked_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "initial")
            subprocess.run(["git", "branch", "codex/generated-change"], cwd=root, check=True)
            findings = scan_git_contribution_governance(root)

        branch_findings = [item for item in findings if item.rule == "codex-prefixed-branch"]
        self.assertEqual(len(branch_findings), 1)
        self.assertEqual(branch_findings[0].path, "<branch-ref>")
        self.assertNotIn("generated-change", str(branch_findings[0].to_dict()))

    def test_meaningful_feature_and_fix_branches_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "initial")
            subprocess.run(["git", "branch", "feature/contribution-gate"], cwd=root, check=True)
            subprocess.run(["git", "branch", "fix/commit-metadata"], cwd=root, check=True)
            findings = scan_git_contribution_governance(root)

        self.assertNotIn("codex-prefixed-branch", {item.rule for item in findings})

    def test_github_ruleset_blocks_the_same_commit_and_branch_metadata(self) -> None:
        ruleset_path = (
            Path(__file__).parents[1]
            / ".github"
            / "rulesets"
            / "contribution-governance.json"
        )
        ruleset = json.loads(ruleset_path.read_text(encoding="utf-8"))
        rules = {rule["type"]: rule["parameters"] for rule in ruleset["rules"]}

        self.assertEqual(ruleset["enforcement"], "active")
        self.assertEqual(ruleset["conditions"]["ref_name"]["include"], ["~ALL"])
        governed = set(ruleset["conditions"]["repository_name"]["include"])
        self.assertTrue({"Meshrix", "LicoUp", "BadTower", "Fabrigent"} <= governed)
        for rule in rules.values():
            self.assertTrue(rule["negate"])
            self.assertEqual(rule["operator"], "regex")

        branch_pattern = re.compile(rules["branch_name_pattern"]["pattern"])
        self.assertIsNotNone(branch_pattern.search("codex/generated-change"))
        self.assertIsNone(branch_pattern.search("feature/contribution-gate"))

        message_pattern = re.compile(rules["commit_message_pattern"]["pattern"])
        self.assertIsNotNone(message_pattern.search("Made-with: Cursor"))
        self.assertIsNotNone(
            message_pattern.search("subject\n\nCo-authored-by: Cursor Bot <bot@example.test>")
        )
        self.assertIsNone(message_pattern.search("document Cursor integration"))
