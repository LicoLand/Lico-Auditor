from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lico_auditor.scanner import scan_text, scan_worktree


def write_fixtures(root: Path, fixtures: dict[str, str]) -> None:
    for relative_path, content in fixtures.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def rules(findings: list[object]) -> list[str]:
    return [getattr(item, "rule") for item in findings]


class LicoupProfileJsonAllowlistTests(unittest.TestCase):
    def test_licoup_profile_allows_client_owned_configuration_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(
                root,
                {
                    ".vscode/settings.json": '{"cmake.ignoreCMakeListsMissing":true}',
                    "apps/desktop/ios/Runner/Assets.xcassets/AppIcon.appiconset/Contents.json": '{"images":[],"info":{"version":1}}',
                    "apps/desktop/assets/update/licoup-update-public-keys.json": '{"keys":{}}',
                    "crates/licoup-native/resources/client-update-public-keys.json": '{"keys":{}}',
                    "crates/licoup-native/resources/adaptive_flywheel/builtin-basic/workflow.json": '{"schema":"v1","states":[],"transitions":[]}',
                    "crates/lico-client-native/resources/agent-conversation-drivers.json": '{"schemaVersion":"1"}',
                    "apps/desktop/macos/Runner/Assets.xcassets/AppIcon.appiconset/SourceManifest.json": '{"icons":[],"schemaVersion":"1","source":"synthetic"}',
                    "crates/licoup-native/src/domain/targets/model_catalog/builtin_catalog.json": '{"agents":[],"description":"synthetic","schemaVersion":"1"}',
                    "crates/lico-client-native/src/domain/targets/model_catalog/builtin_catalog.json": '{"agents":[],"schemaVersion":"1"}',
                    "crates/licoup-native/src/domain/agent_intelligence_catalog/example.json": '{"schema_version":2,"catalog_version":"synthetic","as_of":"2026-01-01","source_url":"https://artificialanalysis.ai"}',
                    "crates/licoup-native/src/domain/provider_model_pricing/pricing_snapshot.json": '{"schema_version":1,"snapshot_date":"2026-01-01","providers":[]}',
                    "crates/licoup-native/src/domain/provider_model_pricing/pricing_catalog.json": '{"agents":[],"last_updated":"2026-01-01","providers":[]}',
                    "docs/plans/Manifest.json": '[{"id":"synthetic-plan"}]',
                    "docs/plans/client-release/Checkpoints.json": '[{"checkpoint":"synthetic"}]',
                    "docs/plan/Manifest.json": '[{"id":"synthetic-plan"}]',
                    "docs/plan/client-release/Checkpoints.json": '[{"checkpoint":"synthetic"}]',
                    "apps/desktop/test/layout/profiles/studio/mobile/studio_mobile_sha256_manifest.json": '{"algorithm":"sha256","goldens":[],"normalization":{},"source":"synthetic"}',
                    "plugins/lico-up-codex/mcp/server.json": '{"mcpServers":{}}',
                    "schemas/client_bridge/manifest.json": '{"families":[],"version":"1"}',
                    "schemas/client_bridge/state.json": '{"operations":[],"version":"1"}',
                    "tools/client-cli-vm-matrix.json": '{"architecture":"arm64","description":"synthetic","schemaVersion":"1","distros":[]}',
                    "tools/client-release-targets.json": '{"schemaVersion":"1","targets":[]}',
                    "tools/client-support-matrix.json": '{"defaults":{},"services":[],"targets":[]}',
                    "tools/client-version.json": '{"buildNumber":"1","productVersion":"0.0.1","schemaVersion":"1"}',
                    "tools/scripts/client-agent-auth-status/probes.json": '{"probes":[],"schemaVersion":"1"}',
                },
            )
            self.assertEqual(scan_worktree(root, profile="licoup"), [])

    def test_licoup_profile_still_rejects_unlisted_data_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(root, {"data/export.json": '{"rows":[]}'})
            self.assertEqual(
                rules(scan_worktree(root, profile="licoup")),
                ["json-data-file-not-allowlisted"],
            )

    def test_licoup_profile_still_rejects_user_record_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(
                root,
                {
                    "tools/client-support-matrix.json": (
                        '{"defaults":{},"users":[{"name":"Alice","email":"alice@example.test"}]}'
                    )
                },
            )
            self.assertIn(
                "user-record-data-shape",
                rules(scan_worktree(root, profile="licoup")),
            )

    def test_plugin_mcp_server_manifest_still_requires_server_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(root, {"plugins/lico-up-codex/mcp/server.json": '{"entries":[]}'})
            self.assertEqual(
                rules(scan_worktree(root, profile="licoup")),
                ["json-config-shape-invalid"],
            )


class LicoupDomainPolicyTests(unittest.TestCase):
    def test_documentation_reference_hosts_allowed_in_docs(self) -> None:
        text = (
            "- [SPIFFE ID](https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/)\n"
            "- [SQLite WAL](https://www.sqlite.org/wal.html)\n"
            "- [Matrix](https://spec.matrix.org/latest/client-server-api/)\n"
            "- [Tokio](https://docs.rs/tokio/latest/tokio/)\n"
        )
        self.assertEqual(scan_text("docs/plans/client-release/Evidence.md", text), [])

    def test_official_vendor_hosts_allowed_in_source_and_catalog(self) -> None:
        catalog_line = '"source": "https://code.claude.com/docs/en/model-config"'
        self.assertEqual(
            scan_text(
                "crates/licoup-native/src/domain/targets/model_catalog/builtin_catalog.json",
                catalog_line,
            ),
            [],
        )
        source_line = 'let mut url = Url::parse("https://api.github.com")'
        self.assertEqual(
            scan_text("crates/licoup-native/src/domain/skill_hub/source.rs", source_line),
            [],
        )

    def test_official_distribution_hosts_allowed_in_tooling(self) -> None:
        matrix_line = '"imageUrl": "https://cloud-images.ubuntu.com/noble/current/noble.img"'
        self.assertEqual(scan_text("tools/client-cli-vm-matrix.json", matrix_line), [])
        bootstrap_line = 'const url = "https://static.rust-lang.org/rustup/dist/x86_64/rustup-init";'
        self.assertEqual(
            scan_text("tools/scripts/client-cli-vm/verify/bootstrap.mjs", bootstrap_line),
            [],
        )

    def test_client_vendor_sources_and_public_api_origins_are_allowed(self) -> None:
        lines = (
            'source = "https://artificialanalysis.ai/methodology"',
            'baseUrl = "https://api.deepseek.com/v1"',
            'baseUrl = "https://api.moonshot.cn/v1"',
            'download = "https://downloads.cursor.com/client.tar.gz"',
            'source = "https://developers.openai.com/api/docs/models"',
            'source = "https://www-cdn.anthropic.com/files/model-card.pdf"',
            'source = "https://docs.x.ai/developers/pricing"',
            'source = "https://dev.opencode.ai/docs/zen"',
            'source = "https://objects.githubusercontent.com/release/item"',
            'source = "https://raw.githubusercontent.com/vendor/project/main/catalog.json"',
            'endpoint = "https://api.telegram.org"',
            'schema = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"',
            'source = "https://api.flutter.dev/flutter/widgets/widgets-library.html"',
            'source = "https://platform.claude.com/docs"',
            'source = "https://platform.deepseek.com/docs"',
            'source = "https://platform.moonshot.cn/docs"',
            'source = "https://hermes-agent.nousresearch.com/docs"',
            'source = "https://openai.github.io/openai-agents-python/"',
            'endpoint = "https://generativelanguage.googleapis.com"',
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(
                    scan_text("crates/licoup-native/src/domain/provider_reference.rs", line),
                    [],
                )

    def test_dotted_code_status_and_conversion_calls_are_not_hosts(self) -> None:
        self.assertEqual(
            scan_text("crates/licoup-native/src/example.rs", "host = host.to_string();"),
            [],
        )
        self.assertEqual(
            scan_text("crates/licoup-native/src/example.rs", "status = snapshot.status();"),
            [],
        )

    def test_docker_internal_names_are_local_development_hosts(self) -> None:
        line = "return `http://host.docker.internal:${this.port}`;"
        self.assertEqual(
            scan_text("tools/scripts/client-secure-mesh-linux-node-matrix/relay/opaque-relay.mjs", line),
            [],
        )

    def test_numeric_dotted_versions_are_not_hosts(self) -> None:
        self.assertEqual(scan_text("crates/licoup-native/Cargo.toml", 'url = "2.5"'), [])

    def test_dotted_method_calls_are_not_hosts(self) -> None:
        self.assertEqual(
            scan_text("crates/licoup-native/src/platform/local_service/endpoint.rs", "let host = host.into();"),
            [],
        )
        self.assertEqual(
            scan_text("crates/licoup-native/src/platform/orchestrator_ipc/mod.rs", "server: self.clone(),"),
            [],
        )
        self.assertEqual(
            scan_text("apps/desktop/lib/src/example.dart", "url = location.href;"),
            [],
        )
        self.assertEqual(
            scan_text("apps/desktop/lib/src/example.dart", "host = trimmed.substring(1);"),
            [],
        )

    def test_historical_client_hosts_are_scoped_to_their_public_contract_paths(self) -> None:
        cases = (
            (
                "crates/lico-client-native/src/domain/mobile_relay.rs",
                'endpoint = "https://old-relay.trycloudflare.com"',
            ),
            (
                "crates/licoup-native/src/domain/mobile_relay/config.rs",
                'endpoint = "https://temporary.trycloudflare.com"',
            ),
            (
                "packages/contracts/client/agent-conversation-adapter.schema.json",
                '"$id": "https://licomesh.dev/schema.json"',
            ),
        )
        for path, line in cases:
            with self.subTest(path=path):
                self.assertEqual(scan_text(path, line), [])
        self.assertEqual(
            rules(
                scan_text(
                    "deployment/relay.env",
                    'endpoint = "https://temporary.trycloudflare.com"',
                )
            ),
            ["disallowed-domain"],
        )

    def test_private_endpoints_still_flagged(self) -> None:
        findings = scan_text(
            "apps/desktop/lib/src/config.dart",
            'const endpoint = "https://contoso.com/internal";',
        )
        self.assertEqual(rules(findings), ["disallowed-domain"])

    def test_non_allowlisted_ip_literals_still_flagged(self) -> None:
        findings = scan_text(
            "crates/licoup-native/src/platform/url_security.rs",
            'const target: &str = "http://198.51.100.42/forward";',
        )
        self.assertEqual(rules(findings), ["ip-literal"])

    def test_loopback_range_is_local_and_not_public_endpoint_metadata(self) -> None:
        self.assertEqual(
            scan_text(
                "crates/licoup-native/src/platform/url_security.rs",
                'const loopback = "http://127.0.0.2/status";',
            ),
            [],
        )

    def test_client_update_negative_ip_fixture_is_not_public_endpoint_metadata(self) -> None:
        findings = scan_text(
            "crates/licoup-native/src/domain/client_update/github_source.rs",
            'let blocked = "http://192.168.1.5/steal";',
        )
        self.assertEqual(findings, [])

    def test_historical_proxy_negative_ip_fixture_is_not_public_endpoint_metadata(self) -> None:
        findings = scan_text(
            "crates/lico-client-native/src/domain/proxy_bridge.rs",
            'let blocked = "http://192.168.1.5/steal";',
        )
        self.assertEqual(findings, [])

    def test_known_client_fixture_paths_do_not_publish_synthetic_home_paths(self) -> None:
        macos_path = "/" + "Users/" + "example/project"
        linux_path = "/" + "home/" + "example/project"
        windows_path = "C:\\" + "Users\\" + "example\\project"
        cases = (
            ("apps/desktop/test/messaging/messaging_details_panel_test.dart", macos_path),
            ("crates/licoup-native/src/platform/agent_workspace.rs", linux_path),
            ("crates/lico-client-native/src/core/acp/tests.rs", windows_path),
        )
        for path, value in cases:
            with self.subTest(path=path):
                self.assertEqual(scan_text(path, value), [])
        self.assertEqual(
            rules(scan_text("crates/licoup-native/src/platform/runtime.rs", macos_path)),
            ["developer-macos-home-path"],
        )


class LicoupSecretPredicateTests(unittest.TestCase):
    def test_rust_path_reexports_and_type_annotations_are_not_secrets(self) -> None:
        self.assertEqual(
            scan_text(
                "crates/licoup-native/src/core/secure_mesh_relay_envelope/mailbox/mod.rs",
                "pub use token::SecureMeshMailboxToken;",
            ),
            [],
        )
        self.assertEqual(
            scan_text(
                "crates/licoup-native/src/domain/mobile_relay/prekey_inventory.rs",
                "    signing_key: &ed25519_dalek::SigningKey,",
            ),
            [],
        )

    def test_opaque_secret_assignments_still_flagged(self) -> None:
        # Fragmented so this test file itself carries no opaque literal.
        secret = "L9v_2" + "Qx!pR7z" + "-M4n$T8b" + "@Y6c"
        findings = scan_text("crates/licoup-native/src/config.rs", f'secret = "{secret}"')
        self.assertEqual(rules(findings), ["secret-assignment"])

    def test_code_expression_named_lead_is_not_business_data(self) -> None:
        self.assertEqual(
            scan_text("crates/licoup-native/src/platform/pty_transport.rs", "lead = buffer[index];"),
            [],
        )

    def test_versioned_credential_handle_is_not_secret_material(self) -> None:
        handle = "api-" + "key:gateway-credentials-v1:credential-" + "11111111-1111-4111-8111-111111111111"
        self.assertEqual(
            scan_text(
                "crates/licoup-native/src/platform/llm_api_key_vault.rs",
                f'account = "{handle}"',
            ),
            [],
        )


class LicoupDocumentationGovernanceTests(unittest.TestCase):
    def test_licoup_release_and_platform_documents_are_formal_paths(self) -> None:
        import subprocess

        from lico_auditor.documentation_rules import documentation_governance_findings

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(
                root,
                {
                    "docs/RELEASE-PACKAGES.md": "# Release packages\n",
                    "docs/RELEASE-PACKAGES.zh-CN.md": "# 发布包\n",
                    "docs/platforms/MACOS-DIRECT-DISTRIBUTION.md": "# macOS\n",
                    "docs/platforms/MACOS-DIRECT-DISTRIBUTION.zh-CN.md": "# macOS\n",
                    "docs/releases/PROMOTION-GATES.md": "# Promotion gates\n",
                    "docs/releases/PROMOTION-GATES.zh-CN.md": "# 晋升门禁\n",
                },
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
            findings = documentation_governance_findings(root, "licoup")
            self.assertNotIn(
                "documentation-formal-path-invalid",
                {item.rule for item in findings},
            )

    def test_localized_formal_sibling_is_a_valid_formal_path(self) -> None:
        import subprocess

        from lico_auditor.documentation_rules import documentation_governance_findings

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_fixtures(
                root,
                {
                    "README.md": (
                        "# Example\n\nEnglish is the normative language. "
                        "Simplified Chinese is the localized language.\n\n"
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
                    "docs/README.md": (
                        "# Documentation\n\n"
                        "- [Runbook](RUNBOOK.md)\n"
                        "- [Compatibility](COMPATIBILITY.md) · [兼容性](COMPATIBILITY.zh-CN.md)\n"
                        "- [Entity Config Layout](ENTITY-CONFIG-LAYOUT.md)\n"
                        "- [Architecture](architecture/OVERVIEW.md)\n"
                        "- [Functionality](functionality/OVERVIEW.md)\n"
                        "- [Protocols](protocols/OVERVIEW.md)\n"
                        "- [Examples](examples/README.md)\n"
                        "- [ADRs](adrs/README.md)\n"
                    ),
                    "docs/RUNBOOK.md": "# Runbook\n",
                    "docs/COMPATIBILITY.md": "# Compatibility\n",
                    "docs/COMPATIBILITY.zh-CN.md": "# 兼容性\n",
                    "docs/ENTITY-CONFIG-LAYOUT.md": "# Entity Config Layout\n",
                    "docs/STATUS.md": "# Status\n",
                    "docs/STATUS.zh-CN.md": "# 状态\n",
                    "docs/architecture/OVERVIEW.md": "# Architecture\n",
                    "docs/functionality/OVERVIEW.md": "# Functionality\n",
                    "docs/protocols/OVERVIEW.md": "# Protocols\n",
                    "docs/examples/README.md": "# Examples\n",
                    "docs/adrs/README.md": "# ADR Index\n",
                    ".gitignore": "docs/plans/\ndocs/reports/\ncache/\nbuild/\n",
                },
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
            findings = documentation_governance_findings(root, "licoup")
            self.assertNotIn(
                "documentation-formal-path-invalid",
                {item.rule for item in findings},
            )


if __name__ == "__main__":
    unittest.main()
