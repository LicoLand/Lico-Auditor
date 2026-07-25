from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from lico_auditor.cli import collect_findings, main
from lico_auditor.contribution_rules import (
    scan_contributor_attribution,
    scan_git_contribution_governance,
)


class ContributionGovernanceTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "audit@example.test"], cwd=root, check=True)

    def commit(
        self,
        root: Path,
        message: str,
        *,
        author_name: str = "Audit Test",
        content: str | None = None,
    ) -> None:
        (root / "tracked.txt").write_text(content if content is not None else message, encoding="utf-8")
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

    def run_json_gate(self, root: Path, *args: str) -> tuple[int, list[dict[str, object]]]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["gate", "--repo", str(root), "--format", "json", *args])
        return status, json.loads(output.getvalue())

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

    def test_no_contribution_skips_commit_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(root, "implement feature\n\nCo-authored-by: Cursor Bot <bot@example.test>")
            findings = collect_findings(root, include_history=True, include_contribution=False)

        self.assertNotIn("cursor-commit-attribution", {item.rule for item in findings})

    def test_cli_current_gate_still_blocks_new_cursor_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(
                root,
                "implement feature\n\nCo-authored-by: Cursor Bot <bot@example.test>",
                content="public",
            )
            status, findings = self.run_json_gate(root)

        self.assertEqual(status, 1)
        self.assertIn("cursor-commit-attribution", {str(item["rule"]) for item in findings})

    def test_cli_history_no_contribution_keeps_content_gate_without_legacy_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.commit(
                root,
                "initial\n\nCo-authored-by: Cursor Bot <bot@example.test>",
                content="public",
            )
            self.commit(root, "advance head")

            clean_status, clean_findings = self.run_json_gate(root, "--history", "--no-contribution")
            self.assertEqual(clean_status, 0)
            self.assertEqual(clean_findings, [])

            evidence = root / "historical.txt"
            evidence.write_text("/" + "Users/example/private", encoding="utf-8")
            subprocess.run(["git", "add", "historical.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "add historical evidence"], cwd=root, check=True)
            evidence.unlink()
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "remove historical evidence"], cwd=root, check=True)

            failed_status, failed_findings = self.run_json_gate(root, "--history", "--no-contribution")

        rules = {str(item["rule"]) for item in failed_findings}
        self.assertEqual(failed_status, 1)
        self.assertIn("developer-macos-home-path", rules)
        self.assertNotIn("cursor-commit-attribution", rules)

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
