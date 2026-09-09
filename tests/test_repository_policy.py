from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from lico_auditor.privacy_rules import (
    REPOSITORY_POLICY_MAX_DECLARATIONS,
    REPOSITORY_POLICY_MAX_DOMAINS,
    parse_repository_policy,
)
from lico_auditor.scanner import scan_history, scan_worktree


def run_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def write_policy(root: Path, policy: dict[str, object]) -> None:
    target = root / ".lico-auditor" / "policy.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(policy), encoding="utf-8")


def exact_config_declarations(count: int) -> list[dict[str, str]]:
    return [
        {"path": f"tools/example/owned-{index:03d}.json", "kind": "config-object"}
        for index in range(count)
    ]


def policy_bytes(declarations: list[dict[str, str]], domains: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 1,
            "allowedJsonPaths": declarations,
            "publicReferenceDomains": [] if domains is None else domains,
        }
    ).encode("utf-8")


class RepositoryPolicyTests(unittest.TestCase):
    def test_declared_config_json_is_admitted_without_central_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [
                        {"path": "tools/example/owned.json", "kind": "config-object"}
                    ],
                    "publicReferenceDomains": [],
                },
            )
            target = root / "tools" / "example" / "owned.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"name":"example","enabled":true}', encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="common"), [])

    def test_declared_string_array_shape_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [
                        {"path": "tools/example/list.json", "kind": "string-array"}
                    ],
                    "publicReferenceDomains": [],
                },
            )
            target = root / "tools" / "example" / "list.json"
            target.parent.mkdir(parents=True)
            target.write_text('["README.md"]', encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="common"), [])

            target.write_text('{"not":"array"}', encoding="utf-8")
            rules = {item.rule for item in scan_worktree(root, profile="common")}
            self.assertIn("json-config-shape-invalid", rules)

    def test_declaration_cannot_admit_user_record_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [
                        {"path": "tools/example/users.json", "kind": "config-object"}
                    ],
                    "publicReferenceDomains": [],
                },
            )
            target = root / "tools" / "example" / "users.json"
            target.parent.mkdir(parents=True)
            target.write_text(
                '{"users":[{"name":"Alice","email":"alice@example.test"}]}',
                encoding="utf-8",
            )
            rules = {item.rule for item in scan_worktree(root, profile="common")}
            self.assertIn("user-record-data-shape", rules)
            self.assertNotIn("json-config-shape-invalid", rules)

    def test_invalid_repository_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [
                        {"path": "../tools/example/owned.json", "kind": "config-object"}
                    ],
                    "publicReferenceDomains": [],
                },
            )
            findings = scan_worktree(root, profile="common")
        self.assertIn(
            ("repository-policy-invalid", "high-risk"),
            {(item.rule, item.severity) for item in findings},
        )

    def test_declared_public_reference_domain_is_scoped_outside_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [],
                    "publicReferenceDomains": ["docs.vendor.contoso.com"],
                },
            )
            (root / "docs").mkdir()
            (root / "docs" / "README.md").write_text(
                "https://docs.vendor.contoso.com/guide",
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "//! Reference: https://docs.vendor.contoso.com/guide\n",
                encoding="utf-8",
            )
            findings = scan_worktree(root, profile="common")
            self.assertEqual(findings, [])

            deployment = root / "deployment" / "settings.env"
            deployment.parent.mkdir(parents=True)
            deployment.write_text("url=https://docs.vendor.contoso.com/guide", encoding="utf-8")
            findings = scan_worktree(root, profile="common")
            self.assertIn("disallowed-domain", {item.rule for item in findings})

    def test_declared_official_docs_domain_admits_skill_paths_not_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [],
                    "publicReferenceDomains": ["docs.language.contoso.com"],
                },
            )
            skill = root / "skills" / "lico-stack-example" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("https://docs.language.contoso.com/guide", encoding="utf-8")
            grouped = root / "skills" / "licoup" / "example" / "references" / "guide.md"
            grouped.parent.mkdir(parents=True)
            grouped.write_text(
                "See https://docs.language.contoso.com/guide",
                encoding="utf-8",
            )
            self.assertEqual(scan_worktree(root, profile="skills"), [])

            deployment = root / "deployment" / "settings.env"
            deployment.parent.mkdir(parents=True)
            deployment.write_text(
                "url=https://docs.language.contoso.com/guide",
                encoding="utf-8",
            )
            findings = scan_worktree(root, profile="skills")
            deployment_findings = [
                item
                for item in findings
                if item.path.replace("\\", "/") == "deployment/settings.env"
            ]
            self.assertTrue(deployment_findings)
            self.assertTrue(
                all(
                    item.rule == "disallowed-domain" and item.severity == "high-risk"
                    for item in deployment_findings
                )
            )

    def test_declared_docs_domain_does_not_admit_undeclared_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": [],
                    "publicReferenceDomains": ["docs.language.contoso.com"],
                },
            )
            skill = root / "skills" / "lico-stack-example" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("https://api.language.contoso.com/v1", encoding="utf-8")
            findings = scan_worktree(root, profile="skills")
            self.assertTrue(findings)
            self.assertTrue(all(item.rule == "disallowed-domain" for item in findings))
            self.assertTrue(all(item.severity == "warning" for item in findings))

    def test_documentation_domain_hits_are_warnings_not_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "docs").mkdir()
            (root / "docs" / "README.md").write_text(
                "See https://docs.contoso.com/guide.",
                encoding="utf-8",
            )
            findings = scan_worktree(root, profile="common")
        self.assertTrue(findings)
        self.assertTrue(all(item.severity == "warning" for item in findings))
        self.assertTrue(all(item.rule == "disallowed-domain" for item in findings))

    def test_repository_policy_parser_rejects_duplicate_and_local_domains(self) -> None:
        policy, error = parse_repository_policy(
            b'{"schemaVersion":1,"allowedJsonPaths":[],'
            b'"publicReferenceDomains":["docs.example.internal"]}'
        )
        self.assertIsNone(policy)
        self.assertIn("public DNS names", error or "")

    def test_sixty_seven_exact_config_objects_are_admitted(self) -> None:
        self.assertEqual(REPOSITORY_POLICY_MAX_DECLARATIONS, 128)
        self.assertEqual(REPOSITORY_POLICY_MAX_DOMAINS, 64)
        declarations = exact_config_declarations(67)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_policy(
                root,
                {
                    "schemaVersion": 1,
                    "allowedJsonPaths": declarations,
                    "publicReferenceDomains": [],
                },
            )
            for declaration in declarations:
                target = root / declaration["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('{"name":"example","enabled":true}', encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="common"), [])

    def test_declared_limit_one_hundred_twenty_eight_is_valid(self) -> None:
        policy, error = parse_repository_policy(policy_bytes(exact_config_declarations(128)))
        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        self.assertEqual(len(policy.declarations), 128)

    def test_one_hundred_twenty_nine_declarations_are_invalid(self) -> None:
        policy, error = parse_repository_policy(policy_bytes(exact_config_declarations(129)))
        self.assertIsNone(policy)
        self.assertIn("at most 128 declarations", error or "")

    def test_invalid_declaration_kind_still_fails_closed(self) -> None:
        policy, error = parse_repository_policy(
            b'{"schemaVersion":1,"allowedJsonPaths":'
            b'[{"path":"tools/example/owned.json","kind":"wildcard"}],'
            b'"publicReferenceDomains":[]}'
        )
        self.assertIsNone(policy)
        self.assertIn("kind must be one of", error or "")

    def test_domain_cap_remains_sixty_four(self) -> None:
        self.assertEqual(REPOSITORY_POLICY_MAX_DOMAINS, 64)
        accepted, accepted_error = parse_repository_policy(
            policy_bytes([], [f"docs{index}.vendor.contoso.com" for index in range(64)])
        )
        self.assertIsNone(accepted_error)
        self.assertIsNotNone(accepted)
        self.assertEqual(len(accepted.public_reference_domains), 64)
        rejected, rejected_error = parse_repository_policy(
            policy_bytes([], [f"docs{index}.vendor.contoso.com" for index in range(65)])
        )
        self.assertIsNone(rejected)
        self.assertIn("at most 64 domains", rejected_error or "")


class ChangedPathHistoryTests(unittest.TestCase):
    def test_retired_non_sensitive_config_json_is_a_history_warning(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run_git(root, "init", "-q")
            run_git(root, "config", "user.name", "Audit Test")
            run_git(root, "config", "user.email", "audit@example.test")

            config = root / "tools" / "example" / "owned.json"
            config.parent.mkdir(parents=True)
            config.write_text('{"name":"retired-config"}', encoding="utf-8")
            run_git(root, "add", "tools")
            run_git(root, "commit", "-q", "-m", "add retired config")

            config.unlink()
            run_git(root, "rm", "--quiet", "tools/example/owned.json")
            run_git(root, "commit", "-q", "-m", "remove retired config")

            findings = scan_history(root, ref="HEAD", profile="common")
        self.assertEqual(
            [(item.rule, item.severity) for item in findings],
            [("json-data-file-not-allowlisted", "warning")],
        )

    def test_retired_user_record_json_stays_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run_git(root, "init", "-q")
            run_git(root, "config", "user.name", "Audit Test")
            run_git(root, "config", "user.email", "audit@example.test")

            config = root / "tools" / "example" / "users.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                '{"users":[{"name":"Alice","email":"alice@example.test"}]}',
                encoding="utf-8",
            )
            run_git(root, "add", "tools")
            run_git(root, "commit", "-q", "-m", "add user records")

            config.unlink()
            run_git(root, "rm", "--quiet", "tools/example/users.json")
            run_git(root, "commit", "-q", "-m", "remove user records")

            findings = scan_history(root, ref="HEAD", profile="common")
        self.assertEqual(
            [(item.rule, item.severity) for item in findings],
            [("json-data-file-not-allowlisted", "high-risk")],
        )

    def test_history_range_scans_introduced_paths_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run_git(root, "init", "-q")
            run_git(root, "config", "user.name", "Audit Test")
            run_git(root, "config", "user.email", "audit@example.test")

            leak = root / "leak.txt"
            leak.write_text("endpoint=https://docs.contoso.com/private", encoding="utf-8")
            run_git(root, "add", "leak.txt")
            run_git(root, "commit", "-q", "-m", "add leak")

            other = root / "other.txt"
            other.write_text("public", encoding="utf-8")
            run_git(root, "add", "other.txt")
            run_git(root, "commit", "-q", "-m", "advance")

            findings = scan_history(root, ref="HEAD~1..HEAD", profile="common")
            self.assertEqual(findings, [])
            full_findings = scan_history(
                root,
                ref="HEAD~1..HEAD",
                profile="common",
                full_tree=True,
            )
            self.assertIn("disallowed-domain", {item.rule for item in full_findings})


if __name__ == "__main__":
    unittest.main()
