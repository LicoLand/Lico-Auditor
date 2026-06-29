from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from licolite_audit.models import AuditReport, AuditTarget
from licolite_audit.scanner import scan_text, scan_worktree


def macos_home_path(suffix: str) -> str:
    return "/" + "Users/" + suffix


def public_ipv4() -> str:
    return ".".join(["198", "49", "23", "144"])


def public_ipv6() -> str:
    return ":".join(["2606", "4700", "4700", "", "1111"])


def private_ipv4() -> str:
    return ".".join(["10", "0", "0", "5"])


def documentation_ipv4() -> str:
    return ".".join(["192", "0", "2", "10"])


def loopback_ipv4() -> str:
    return ".".join(["127", "0", "0", "1"])


def loopback_ipv6() -> str:
    return ":" * 2 + "1"


def disallowed_domain() -> str:
    return "contoso" + ".com"


def private_key_marker() -> str:
    return "-----BEGIN " + "PRIVATE KEY" + "-----"


def secret_value() -> str:
    return "s3cr3t_" + "A" * 24


def jwt_value() -> str:
    return ".".join(["eyJ" + "A" * 16, "B" * 20, "C" * 20])


def cloud_access_key() -> str:
    return "AKIA" + "A" * 16


def credential_url() -> str:
    return "postgres" + "://user:password@localhost/db"


def system_path() -> str:
    return "/" + "etc/ssh/sshd_config"


def cloud_host_label() -> str:
    return "lico" + "-host"


class PrivacyGateTests(unittest.TestCase):
    def test_finding_redacts_value_and_keeps_fingerprint(self) -> None:
        leaked_path = macos_home_path("example/private")
        findings = scan_text("fixture.txt", f"path={leaked_path}")
        self.assertEqual(len(findings), 1)
        rendered = findings[0].to_dict()
        self.assertEqual(rendered["rule"], "developer-macos-home-path")
        self.assertNotIn(leaked_path, str(rendered))
        self.assertTrue(rendered["fingerprint"])

    def test_personal_email_is_out_of_current_scope(self) -> None:
        findings = scan_text("mail.eml", "From: Alice <alice@contoso.com>")
        self.assertEqual(findings, [])

    def test_loopback_ip_literals_pass(self) -> None:
        text = " ".join([loopback_ipv4(), loopback_ipv6()])
        self.assertEqual(scan_text("fixture.txt", text), [])

    def test_any_non_loopback_ip_literal_fails(self) -> None:
        findings = scan_text("fixture.txt", f"{public_ipv4()} {private_ipv4()} {documentation_ipv4()} {public_ipv6()}")
        self.assertEqual([item.rule for item in findings], ["ip-literal", "ip-literal", "ip-literal", "ip-literal"])

    def test_allowed_domains_pass(self) -> None:
        findings = scan_text("fixture.txt", "url=https://licolite.com host=api.licolite.app endpoint=http://localhost:3000")
        self.assertEqual(findings, [])

    def test_disallowed_domains_fail(self) -> None:
        findings = scan_text("fixture.txt", f"url=https://{disallowed_domain()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "disallowed-domain")

    def test_private_key_material_fails(self) -> None:
        findings = scan_text("key.pem", private_key_marker())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "private-key-material")

    def test_secret_assignments_fail(self) -> None:
        findings = scan_text("settings.env", f"client_secret={secret_value()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "secret-assignment")

    def test_placeholder_secret_assignments_pass(self) -> None:
        findings = scan_text("settings.env", "client_secret=REDACTED_PLACEHOLDER_VALUE")
        self.assertEqual(findings, [])

    def test_auth_header_and_jwt_fail(self) -> None:
        findings = scan_text("fixture.txt", f"Authorization: Bearer {secret_value()} token={jwt_value()}")
        self.assertEqual([item.rule for item in findings], ["auth-header-secret", "jwt-token", "secret-assignment"])

    def test_cloud_access_key_fails(self) -> None:
        findings = scan_text("fixture.txt", cloud_access_key())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "cloud-access-token")

    def test_credential_url_fails_even_for_allowed_host(self) -> None:
        findings = scan_text("fixture.txt", credential_url())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "credential-url")

    def test_system_and_deployment_paths_fail(self) -> None:
        findings = scan_text("deployment/production/readme.md", system_path())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "system-or-deployment-path")

    def test_cloud_server_provisioning_assignment_fails(self) -> None:
        findings = scan_text("tools/scripts/vultr-ip-finder.ps1", f"Hostname={cloud_host_label()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "cloud-server-provisioning-setting")

    def test_provider_uuid_only_fails_in_deployment_material(self) -> None:
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        self.assertEqual(scan_text("fixtures/data.json", uuid), [])
        findings = scan_text("deployment/production/provider.json", uuid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "provider-resource-id")

    def test_worktree_skips_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "node_modules/pkg").mkdir(parents=True)
            (root / "node_modules/pkg/index.js").write_text(f"path={macos_home_path('example/private')}", encoding="utf-8")
            self.assertEqual(scan_worktree(root), [])

    def test_report_target_does_not_emit_absolute_path(self) -> None:
        local_path = macos_home_path("example/licolite")
        report = AuditReport(AuditTarget(repo_root=Path(local_path), ref="HEAD"))
        rendered = report.to_dict()
        self.assertEqual(rendered["target"]["repo"], "licolite")
        self.assertNotIn(local_path, str(rendered))


if __name__ == "__main__":
    unittest.main()
