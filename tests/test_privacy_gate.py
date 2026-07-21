from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lico_auditor.models import AuditReport, AuditTarget
from lico_auditor.scanner import resolve_scan_profile, scan_history, scan_text, scan_worktree


def macos_home_path(suffix: str) -> str:
    return "/" + "Users/" + suffix


def public_ipv4() -> str:
    return ".".join(["198", "51", "100", "42"])


def public_ipv6() -> str:
    return "[" + ":".join(["2001", "db8", "", "42"]) + "]"


def private_ipv4() -> str:
    return ".".join(["10", "0", "0", "5"])


def documentation_ipv4() -> str:
    return ".".join(["192", "0", "2", "10"])


def loopback_ipv4() -> str:
    return ".".join(["127", "0", "0", "1"])


def wildcard_ipv4() -> str:
    return ".".join(["0", "0", "0", "0"])


def loopback_ipv6() -> str:
    return ":" * 2 + "1"


def disallowed_domain() -> str:
    return "contoso" + ".com"


def private_key_marker() -> str:
    return "-----BEGIN " + "PRIVATE KEY" + "-----"


def secret_value() -> str:
    return "s3cr3t_" + "A" * 24


def opaque_secret_value() -> str:
    return "L9v_2Qx!pR7z-M4n$T8b@Y6c"


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


def business_customer_name() -> str:
    return "Contoso" + "Bank"


def business_revenue_assignment() -> str:
    return "revenue=" + "100000"


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
        text = " ".join([wildcard_ipv4(), loopback_ipv4(), loopback_ipv6()])
        self.assertEqual(scan_text("fixture.txt", text), [])

    def test_ipv6_rule_ignores_language_separators(self) -> None:
        self.assertEqual(scan_text("src/lib.rs", "use aead::Aead; const sep = '::';"), [])

    def test_any_non_loopback_ip_literal_fails(self) -> None:
        findings = scan_text("fixture.txt", f"{public_ipv4()} {private_ipv4()} {documentation_ipv4()} {public_ipv6()}")
        self.assertEqual([item.rule for item in findings], ["ip-literal", "ip-literal", "ip-literal", "ip-literal"])

    def test_public_github_pages_dns_records_are_allowed_only_at_the_canonical_path(self) -> None:
        records = f"example.test. IN A {public_ipv4()}\nexample.test. IN AAAA {public_ipv6()}"
        self.assertEqual(scan_text("dns/cloudflare-github-pages.txt", records), [])
        self.assertEqual(
            [item.rule for item in scan_text("dns/other-zone.txt", records)],
            ["ip-literal", "ip-literal"],
        )

    def test_config_scanner_range_table_does_not_self_report(self) -> None:
        text = "blocked = ['10.0.0.0', '203.0.113.255']"
        self.assertEqual(scan_text("tools/config-scanner.mjs", text), [])

    def test_svg_path_data_does_not_create_ip_literal_findings(self) -> None:
        text = '<svg><path d="M14.08 13.98c.87.65 2.17.22.98-.97"/></svg>'
        self.assertEqual(scan_text("index.html", text), [])

    def test_html_plain_ip_literals_still_fail(self) -> None:
        findings = scan_text("index.html", "endpoint=203.0.113.10")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "ip-literal")

    def test_allowed_domains_pass(self) -> None:
        findings = scan_text("fixture.txt", "url=https://licomesh.com host=api.licomesh.app org=https://licoland.com endpoint=http://localhost:3000")
        self.assertEqual(findings, [])

    def test_disallowed_domains_fail(self) -> None:
        findings = scan_text("fixture.txt", f"url=https://{disallowed_domain()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "disallowed-domain")

    def test_dotted_code_identifiers_are_not_domains(self) -> None:
        text = "server = http.createServer(); baseUrl = settings.baseUrl; value = process.argv"
        self.assertEqual(scan_text("src/app.mjs", text), [])

    def test_bare_external_host_assignments_still_fail(self) -> None:
        findings = scan_text("settings.env", f"host=api.{disallowed_domain()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "disallowed-domain")

    def test_reserved_synthetic_domains_pass(self) -> None:
        text = "url=https://api.example.test endpoint=https://service.example.com"
        self.assertEqual(scan_text("src/examples.mjs", text), [])
        self.assertEqual(scan_text("src/examples.mjs", "endpoint=https://example.service"), [])

    def test_local_development_domains_pass_outside_deployment(self) -> None:
        self.assertEqual(scan_text("crates/client/src/targets.rs", "url=http://device.local:3000"), [])
        findings = scan_text("deployment/production/settings.env", "url=http://device.local:3000")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "disallowed-domain")

    def test_public_reference_domains_pass_only_in_reference_contexts(self) -> None:
        self.assertEqual(scan_text("README.md", "https://github.com/LicoLand/LicoMesh"), [])
        self.assertEqual(scan_text("index.html", "https://www.npmjs.com/package/pactium"), [])
        self.assertEqual(scan_text("skills/lico-dev/references/public.md", "https://github.com/LicoLand/LicoMesh"), [])
        self.assertEqual(scan_text("skills/lico-dev/references/public.md", "https://csrc.nist.gov/pubs/example"), [])
        self.assertEqual(scan_text("skills/lico-dev/references/public.md", "https://www.rfc-editor.org/rfc/example"), [])
        findings = scan_text("deployment/production/settings.env", "url=https://github.com/LicoLand/LicoMesh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "disallowed-domain")

    def test_standard_namespace_domains_pass_in_source(self) -> None:
        self.assertEqual(scan_text("apps/console/Icon.vue", '<svg xmlns="http://www.w3.org/2000/svg"></svg>'), [])

    def test_operational_script_endpoint_urls_fail(self) -> None:
        findings = scan_text("tools/scripts/deploy.sh", "curl https://$DEPLOY_HOST:8443/health")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "operational-endpoint-url")

        findings = scan_text("scripts/probe.sh", "curl http://internal-admin:9000/health")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "operational-endpoint-url")

        findings = scan_text("tools/server-scripts/probe.sh", "curl http://internal-admin:9000/health")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "operational-endpoint-url")

    def test_allowed_operational_script_endpoint_urls_pass(self) -> None:
        text = "curl http://localhost:3000/health && curl https://api.licomesh.com/health && curl http://<host>:9000/health"
        self.assertEqual(scan_text("tools/scripts/probe.sh", text), [])
        self.assertEqual(scan_text("tools/server-scripts/probe.mjs", "fetch('http://lico-runtime-download-service:19080/health')"), [])

    def test_business_sensitive_assignments_fail(self) -> None:
        text = f"customer_name={business_customer_name()} {business_revenue_assignment()}"
        findings = scan_text("docs/private/accounts.md", text)
        self.assertEqual([item.rule for item in findings], ["business-sensitive-assignment", "business-sensitive-assignment"])

    def test_business_sensitive_placeholders_pass(self) -> None:
        text = "customer_name=REDACTED_PLACEHOLDER tenant_id=${TENANT_ID} revenue=example"
        self.assertEqual(scan_text("docs/examples/accounts.md", text), [])

    def test_business_sensitive_code_expressions_pass(self) -> None:
        text = "customerName = input.customerName\nsubscription_id = config.subscriptionId"
        self.assertEqual(scan_text("src/customer.ts", text), [])

    def test_production_metadata_assignments_fail_in_operational_paths(self) -> None:
        text = "cluster_name=prod-primary region=us-east-1 service_name=backend-api"
        findings = scan_text("deployment/production/settings.env", text)
        self.assertEqual(
            [item.rule for item in findings],
            [
                "production-metadata-assignment",
                "production-metadata-assignment",
                "production-metadata-assignment",
            ],
        )

    def test_production_metadata_placeholders_pass(self) -> None:
        current_text = "cluster_name=example-cluster region=${REGION} service_name=licomesh"
        ecosystem_text = "service_name=lico-auditor"
        self.assertEqual(scan_text("tools/server-scripts/deploy.sh", current_text), [])
        self.assertEqual(scan_text("tools/server-scripts/deploy.sh", ecosystem_text), [])

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

    def test_secret_references_and_code_expressions_pass(self) -> None:
        text = "secretRef=runtime.secretRef credentialRef=credential:fixture-source token=await createToken() apiKey=settings?.customModelApiKey signing_key=this.signingKey"
        self.assertEqual(scan_text("src/security.mjs", text), [])

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

    def test_dependency_lockfiles_ignore_public_registry_noise(self) -> None:
        text = "resolved=https://registry.npmjs.org/example package=https://github.com/example/project"
        self.assertEqual(scan_text("package-lock.json", text), [])
        self.assertEqual(scan_text("Cargo.lock", text), [])
        self.assertEqual(scan_text("fixtures/package.lock", text), [])

    def test_dependency_lockfiles_still_block_credentials(self) -> None:
        findings = scan_text("package-lock.json", credential_url())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "credential-url")

    def test_synthetic_tests_ignore_network_and_system_path_noise(self) -> None:
        text = f"url=https://{disallowed_domain()} {public_ipv4()} path={system_path()}"
        self.assertEqual(scan_text("tests/vitest/server/example.test.mjs", text), [])
        self.assertEqual(scan_text("fixtures/platform/example_test.mjs", text), [])

    def test_synthetic_tests_still_block_real_secret_shapes(self) -> None:
        findings = scan_text("tests/vitest/server/example.test.mjs", f"client_secret={opaque_secret_value()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "secret-assignment")

    def test_verify_scripts_are_synthetic_but_still_scan_secrets(self) -> None:
        synthetic = f"url=https://{disallowed_domain()} {public_ipv4()} path={system_path()}"
        self.assertEqual(scan_text("tools/server-scripts/verify-example.mjs", synthetic), [])

        findings = scan_text("tools/server-scripts/verify-example.mjs", f"client_secret={opaque_secret_value()}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "secret-assignment")

    def test_synthetic_tests_still_block_developer_home_paths(self) -> None:
        findings = scan_text("tests/vitest/server/example.test.mjs", macos_home_path("example/private"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "developer-macos-home-path")

    def test_generic_windows_developer_paths_fail_without_private_markers(self) -> None:
        findings = scan_text("README.md", "path=C:\\Users\\example\\Projects\\sample-app\\config.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "developer-windows-workspace-path")

    def test_git_failure_reports_do_not_echo_local_runtime_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            findings = scan_history(root)
        self.assertEqual(len(findings), 1)
        rendered = findings[0].to_dict()
        self.assertEqual(rendered["rule"], "git-history-unavailable")
        self.assertNotIn(raw, str(rendered))
        self.assertTrue(rendered["fingerprint"])

    def test_system_and_deployment_paths_fail(self) -> None:
        findings = scan_text("deployment/production/readme.md", system_path())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "system-or-deployment-path")

    def test_source_code_generic_system_paths_pass(self) -> None:
        findings = scan_text("packages/foundation/src/path-defaults.mjs", "const tmp = '/tmp/licomesh';")
        self.assertEqual(findings, [])

    def test_local_compose_container_paths_pass(self) -> None:
        self.assertEqual(scan_text("docker-compose.yml", "LICO_SERVER_DATA_DIR: /opt/lico/data"), [])

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
        local_path = macos_home_path("example/licomesh")
        report = AuditReport(AuditTarget(repo_root=Path(local_path), ref="HEAD"))
        rendered = report.to_dict()
        self.assertEqual(rendered["target"]["project"], "lico")
        self.assertEqual(rendered["target"]["repo"], "licomesh")
        self.assertNotIn(local_path, str(rendered))

    def test_unknown_json_data_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "exports").mkdir()
            (root / "exports/users.json").write_text('{"users":[{"name":"Alice","email":"alice@example.test"}]}', encoding="utf-8")
            findings = scan_worktree(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "json-data-file-not-allowlisted")

    def test_data_export_files_fail_even_when_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "exports").mkdir()
            (root / "exports/users.jsonl").write_text('{"name":"Alice"}\n', encoding="utf-8")
            (root / "exports/app.sqlite").write_bytes(b"SQLite format 3\0")
            findings = scan_worktree(root)
        self.assertEqual([item.rule for item in findings], ["database-or-binary-data-file", "data-file-not-allowed"])

    def test_strict_config_directory_rejects_non_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_dir = root / "packages/foundation/config"
            config_dir.mkdir(parents=True)
            (config_dir / "notes.md").write_text("not a config object", encoding="utf-8")
            findings = scan_worktree(root, profile="platform")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "config-directory-non-json-file")

    def test_platform_profile_allows_approved_config_support_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_dir = root / "packages/foundation/config/entity-config"
            registry_dir = root / "tools/registry"
            config_dir.mkdir(parents=True)
            registry_dir.mkdir(parents=True)
            (config_dir / "README.md").write_text("configuration docs", encoding="utf-8")
            (registry_dir / "index.mjs").write_text("export {};\n", encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="platform"), [])

    def test_allowlisted_json_config_shape_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_dir = root / "packages/foundation/config/entity-config/tools"
            module_dir = root / "modules/default"
            config_dir.mkdir(parents=True)
            module_dir.mkdir(parents=True)
            (config_dir / "manifest.json").write_text('{"schemaVersion":"1","kind":"manifest"}', encoding="utf-8")
            (module_dir / "module.json").write_text('{"module_id":"default","module_type":"default"}', encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="platform"), [])

    def test_platform_profile_allows_fixed_json_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "apps/console/appearance-presets").mkdir(parents=True)
            (root / "packages/foundation/src/workflow/state-machine/definitions").mkdir(parents=True)
            (root / "apps/console/appearance-presets/default-system.json").write_text(
                '{"schemaVersion":"1","id":"default","label":"Default","lightPresetId":"light","darkPresetId":"dark"}',
                encoding="utf-8",
            )
            (root / "packages/foundation/src/workflow/state-machine/definitions/example.json").write_text(
                '{"machineId":"example","initialState":"draft","states":{},"events":[]}',
                encoding="utf-8",
            )
            self.assertEqual(scan_worktree(root, profile="platform"), [])

    def test_auto_profile_recognizes_renamed_repo_directories(self) -> None:
        self.assertEqual(resolve_scan_profile(Path("LicoMesh")), "platform")
        self.assertEqual(resolve_scan_profile(Path("LicoArc")), "client")
        self.assertEqual(resolve_scan_profile(Path("lico-dev")), "skills")
        self.assertEqual(resolve_scan_profile(Path("Lico-Auditor")), "common")

    def test_client_profile_allows_licoarc_contract_and_asset_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixtures = {
                "packages/contracts/client/semantic-conversation.schema.json": '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}',
                "apps/desktop/assets/appearance-presets/default-system.json": '{"id":"default-system","label":"Default"}',
                "tools/scripts/config/secure-mesh-client-boundary.json": '{"schemaVersion":"1","boundary":"client"}',
            }
            for relative_path, content in fixtures.items():
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="client"), [])

    def test_website_profile_does_not_inherit_platform_config_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_dir = root / "packages/foundation/config"
            config_dir.mkdir(parents=True)
            (config_dir / "manifest.json").write_text('{"schemaVersion":"1","kind":"manifest"}', encoding="utf-8")
            findings = scan_worktree(root, profile="website")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "json-data-file-not-allowlisted")

    def test_skills_profile_allows_skill_template_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            asset_dir = root / "skills/lico-external-service-plugin/assets"
            asset_dir.mkdir(parents=True)
            (asset_dir / "rest-service.template.json").write_text(
                '{"kind":"rest-service","serviceId":"example","serviceName":"example","tools":[]}',
                encoding="utf-8",
            )
            self.assertEqual(scan_worktree(root, profile="skills"), [])

    def test_skills_profile_allows_only_canonical_repository_json_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixtures = {
                "config/repositories.json": '{"schemaVersion":1,"repositories":[]}',
                "skills/catalog.json": '{"schemaVersion":1,"skills":[]}',
                "skills/skills.lock.json": '{"schemaVersion":1,"skills":{}}',
                "workflows/catalog.json": '{"schemaVersion":1,"profiles":{},"tasks":[]}',
            }
            for relative_path, content in fixtures.items():
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            self.assertEqual(scan_worktree(root, profile="skills"), [])

    def test_common_profile_rejects_skill_template_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            asset_dir = root / "skills/lico-external-service-plugin/assets"
            asset_dir.mkdir(parents=True)
            (asset_dir / "rest-service.template.json").write_text(
                '{"kind":"rest-service","serviceId":"example","serviceName":"example","tools":[]}',
                encoding="utf-8",
            )
            findings = scan_worktree(root, profile="common")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "json-data-file-not-allowlisted")

    def test_allowlisted_config_rejects_user_record_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_dir = root / "packages/foundation/config"
            config_dir.mkdir(parents=True)
            (config_dir / "default-users.json").write_text(
                '{"schemaVersion":"1","users":[{"name":"Alice","email":"alice@example.test"}]}',
                encoding="utf-8",
            )
            findings = scan_worktree(root, profile="platform")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "user-record-data-shape")


if __name__ == "__main__":
    unittest.main()
