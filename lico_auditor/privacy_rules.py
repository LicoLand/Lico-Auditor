from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


IGNORED_DIR_NAMES = {
    ".dart_tool",
    ".git",
    ".gradle",
    ".pytest_cache",
    ".pub",
    ".pub-cache",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "ephemeral",
    "node_modules",
    "pods",
    "target",
}

IGNORED_FILE_NAMES = {
    ".flutter-plugins",
    ".flutter-plugins-dependencies",
    "flutter_export_environment.sh",
    "generated_plugin_registrant.cc",
    "generated_plugin_registrant.h",
    "generated_plugins.cmake",
    "local.properties",
}

TEXT_EXTENSIONS = {
    "",
    ".c",
    ".cc",
    ".cjs",
    ".conf",
    ".config",
    ".cpp",
    ".crt",
    ".css",
    ".csv",
    ".dart",
    ".dockerignore",
    ".env",
    ".example",
    ".gitignore",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsonl",
    ".kt",
    ".key",
    ".lock",
    ".md",
    ".mjs",
    ".pem",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".sql",
    ".svg",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
DATA_FILE_EXTENSIONS = {
    ".arrow",
    ".avro",
    ".bak",
    ".csv",
    ".db",
    ".dump",
    ".feather",
    ".jsonl",
    ".ndjson",
    ".orc",
    ".parquet",
    ".sql",
    ".sqlite",
    ".sqlite3",
    ".tsv",
    ".xls",
    ".xlsx",
}
BINARY_DATA_FILE_EXTENSIONS = {
    ".arrow",
    ".avro",
    ".db",
    ".feather",
    ".orc",
    ".parquet",
    ".sqlite",
    ".sqlite3",
    ".xls",
    ".xlsx",
}
DEPENDENCY_LOCKFILE_NAMES = {
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pubspec.lock",
    "yarn.lock",
}
LOCKFILE_SECRET_RULES = frozenset(
    {
        "auth-header-secret",
        "cloud-access-token",
        "credential-url",
        "jwt-token",
        "private-key-material",
        "ssh-public-key-material",
    }
)
SYNTHETIC_TEST_NOISE_RULES = frozenset(
    {
        "business-sensitive-assignment",
        "disallowed-domain",
        "ip-literal",
        "operational-endpoint-url",
        "production-metadata-assignment",
        "system-or-deployment-path",
    }
)
STRICT_JSON_CONFIG_PREFIXES = (
    "packages/foundation/config/",
    "packages/server-runtime/config/",
    "tools/registry/",
)
ALLOWED_NON_JSON_CONFIG_PATHS = {
    "packages/foundation/config/deployment/README.md",
    "packages/foundation/config/entity-config/README.md",
    "packages/foundation/config/entity-config/playbooks/knowledge-playbook-framework/README.md",
    "packages/foundation/config/entity-config/runbooks/project-release-runbook/README.md",
    "packages/foundation/config/frontend-feature-registry.yaml",
    "packages/server-runtime/config/context-profiles/test.mjs",
    "tools/registry/architecture-layout-facade.mjs",
    "tools/registry/architecture-layout-manifest.mjs",
    "tools/registry/index.mjs",
    "tools/registry/source-layout-manifest.mjs",
    "tools/registry/test-suite-reachability.mjs",
}
# List-shaped JSON registries: conformance vectors, local-only planning
# checkpoint registries, and capability acceptance checkpoint registries.
JSON_LIST_SHAPE_PREFIXES = (
    "conformance/",
    "docs/plans/",
    "tools/registry/capability-acceptance-checkpoints/",
)
# Object-shaped JSON whose shape is owned locally: gitignored local-only
# plan/report assets and contract test fixtures carry no governed shape.
JSON_LOCAL_OR_FIXTURE_SHAPE_PREFIXES = (
    "docs/plans/",
    "docs/reports/",
    "packages/contracts/src/fixtures/",
)
JSON_TEMPLATE_PREFIXES = (
    "fixtures/external-services/",
)
ALLOWED_JSON_FILE_NAMES = {
    "package-lock.json",
    "package.json",
    "tsconfig.json",
}
USER_RECORD_KEYS = {
    "address",
    "avatar",
    "birthday",
    "company",
    "department",
    "email",
    "full_name",
    "fullname",
    "identity",
    "mail",
    "mobile",
    "name",
    "openid",
    "phone",
    "profile",
    "real_name",
    "realname",
    "ssn",
    "tel",
    "user",
    "user_id",
    "userid",
    "username",
}
USER_RECORD_CONTAINER_KEYS = {
    "accounts",
    "contacts",
    "customers",
    "data",
    "employees",
    "items",
    "members",
    "people",
    "records",
    "rows",
    "users",
}
CONFIG_SHAPE_MARKER_KEYS = {
    "$id",
    "$schema",
    "bundleType",
    "capabilities",
    "compression",
    "compilerOptions",
    "contextWindowTokens",
    "defaultForAgents",
    "defaults",
    "dependencies",
    "description",
    "darkPresetId",
    "displayName",
    "downloads",
    "entries",
    "entityType",
    "events",
    "files",
    "frameworks",
    "grantable",
    "historyBudget",
    "id",
    "images",
    "info",
    "initialState",
    "items",
    "javaBinPath",
    "kind",
    "label",
    "lightPresetId",
    "manifest",
    "machineId",
    "maxRisk",
    "modelAlias",
    "module_id",
    "module_type",
    "name",
    "operations",
    "packages",
    "profiles",
    "profileId",
    "provider",
    "protocolVersion",
    "openapi",
    "properties",
    "requiredScopes",
    "routes",
    "schemaVersion",
    "scripts",
    "selectionPolicy",
    "serverUrl",
    "serviceId",
    "serviceName",
    "states",
    "strategies",
    "strategy",
    "targets",
    "templates",
    "tikaJarPath",
    "toolsets",
    "target_repositories",
    "type",
    "validation",
    "version",
    "waitServer",
}


def _join(parts: Iterable[str]) -> str:
    return "".join(parts)


MACOS_HOME_PREFIX = _join(["/", "Users", "/"])
LINUX_HOME_PREFIX = _join(["/", "home", "/"])
ASCII_ACCOUNT_NAME_PATTERN = r"[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_$-])?"
PATH_COMPONENT_TERMINATOR_PATTERN = r"(?=[/\\\s`'\"),;:\]}>!?]|$)"
GITHUB_MESHRIX_REMOTE = _join(["https://", "github", ".com/LicoLand/Meshrix.git"])
GITHUB_MESHRIX_SERVICES_REMOTE = _join(["https://", "github", ".com/LicoLand/Meshrix-Services.git"])
GITHUB_MESHRIX_PLUGINS_REMOTE = _join(["https://", "github", ".com/LicoLand/Meshrix-Plugins.git"])
GITHUB_LICOUP_REMOTE = _join(["https://", "github", ".com/LicoLand/LicoUp.git"])
GITHUB_BADTOWER_REMOTE = _join(["https://", "github", ".com/LicoLand/BadTower.git"])
GITHUB_FABRIGENT_REMOTE = _join(["https://", "github", ".com/LicoLand/Fabrigent.git"])
GITHUB_LICOARC_PLUGINS_REMOTE = _join(["https://", "github", ".com/LicoLand/LicoArc-Plugins.git"])
GITHUB_LICO_DEV_REMOTE = _join(["https://", "github", ".com/LicoLand/Lico-Dev.git"])
GITHUB_ORG_PROFILE_REMOTE = _join(["https://", "github", ".com/LicoLand/.github.git"])
GITHUB_SITE_REMOTES = {
    domain: _join(["https://", "github", f".com/LicoLand/{domain}.git"])
    for domain in (
        "lico.land",
        "licoarc.com",
        "licoland.com",
        "licomesh.com",
        "licoup.com",
        "licoup.net",
        "meshrix.io",
    )
}
AUDITED_GITHUB_REMOTES = {
    "Meshrix": GITHUB_MESHRIX_REMOTE,
    "Meshrix-Services": GITHUB_MESHRIX_SERVICES_REMOTE,
    "Meshrix-Plugins": GITHUB_MESHRIX_PLUGINS_REMOTE,
    "LicoUp": GITHUB_LICOUP_REMOTE,
    "BadTower": GITHUB_BADTOWER_REMOTE,
    "Fabrigent": GITHUB_FABRIGENT_REMOTE,
    "LicoArc-Plugins": GITHUB_LICOARC_PLUGINS_REMOTE,
    "lico-dev": GITHUB_LICO_DEV_REMOTE,
    "Lico-Dev": GITHUB_LICO_DEV_REMOTE,
    ".github": GITHUB_ORG_PROFILE_REMOTE,
    **GITHUB_SITE_REMOTES,
}
ALLOWED_HOSTS = {"localhost", "0.0.0.0", "127.0.0.1", "::1"}
ALLOWED_IPV4_LITERALS = {"0.0.0.0", "127.0.0.1"}
# Provider-published link-local metadata endpoints (cloud instance metadata,
# container task metadata, and pod identity agents). Egress-deny policies list
# these well-known constants; they never identify our own infrastructure.
PROVIDER_METADATA_IPV4_LITERALS = {
    _join(["169", ".254.169.254"]),
    _join(["169", ".254.170.2"]),
    _join(["169", ".254.170.23"]),
}
ALLOWED_DOMAIN_SUFFIXES = (
    "lico.land",
    "licoarc.com",
    "licoland.com",
    "licomesh.com",
    "licoup.com",
    "licoup.net",
    "meshrix.io",
)
CODE_LIKE_HOST_FINAL_LABELS = {
    "argv",
    "arraybuffer",
    "baseurl",
    "clone",
    "config",
    "createserver",
    "domain",
    "endpoint",
    "equal",
    "find",
    "host",
    "hostname",
    "includes",
    "into",
    "join",
    "json",
    "lock",
    "match",
    "metadata",
    "mjs",
    "origin",
    "payload",
    "meshrix",
    "platform",
    "replace",
    "server",
    "servers",
    "setdefault",
    "sh",
    "split",
    "statustext",
    "stderr",
    "stdout",
    "svg",
    "toml",
    "tostring",
    "trim",
    "ts",
    "txt",
    "upstream",
    "url",
    "yaml",
    "yml",
}
PUBLIC_REFERENCE_HOSTS = {
    "arm-software.github.io",
    "astral.sh",
    "caddyserver.com",
    "cheatsheetseries.owasp.org",
    "core.telegram.org",
    "dart.dev",
    "desktop.docker.com",
    "developer.android.com",
    "developer.apple.com",
    "csrc.nist.gov",
    "docs.flutter.dev",
    "docs.langchain.com",
    "docs.microsoft.com",
    "docs.sigstore.dev",
    "docs.oasis-open.org",
    "docs.openssl.org",
    "docs.rs",
    "downloads.digitalcorpora.org",
    "flutter.dev",
    "fsf.org",
    "github.com",
    "img.shields.io",
    "json-schema.org",
    "keepachangelog.com",
    "kilo.ai",
    "kubernetes.io",
    "learn.microsoft.com",
    "pi.dev",
    "rfc-editor.org",
    "signal.org",
    "source.android.com",
    "spec.matrix.org",
    "specifications.freedesktop.org",
    "spiffe.io",
    "theupdateframework.github.io",
    "modelcontextprotocol.io",
    "nginx.org",
    "nodejs.org",
    "openid.net",
    "opentelemetry.io",
    "pub.dev",
    "raw.githubusercontent.com",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "schemas.android.com",
    "schemas.openxmlformats.org",
    "semver.org",
    "sqlite.org",
    "unofficial-builds.nodejs.org",
    "vuejs.org",
    "wiki.gnome.org",
    "www.apple.com",
    "www.conventionalcommits.org",
    "www.envoyproxy.io",
    "www.gnu.org",
    "www.microsoft.com",
    "www.openpolicyagent.org",
    "www.python.org",
    "www.rust-lang.org",
    "www.rfc-editor.org",
    "www.sqlite.org",
    "www.w3.org",
}
GLOBAL_STANDARD_REFERENCE_HOSTS = {
    "cyclonedx.org",
    "json-schema.org",
    "mobyproject.org",
    "schemas.android.com",
    "schemas.openxmlformats.org",
    "slsa.dev",
    "www.w3.org",
}
PUBLIC_PACKAGE_HOSTS = {
    "gerrit-releases.storage.googleapis.com",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "registry.npmjs.org",
    "www.npmjs.com",
}
PUBLIC_INTEGRATION_HOSTS = {
    "accounts.google.com",
    "api.dropboxapi.com",
    "api.githubcopilot.com",
    "api.openai.com",
    "auth.openai.com",
    "chatgpt.com",
    "content.dropboxapi.com",
    "developers.google.com",
    "graph.microsoft.com",
    "learn.microsoft.com",
    "login.microsoftonline.com",
    "oauth2.googleapis.com",
    "token.actions.githubusercontent.com",
    "www.dropbox.com",
    "www.googleapis.com",
}
PUBLIC_SOURCE_REFERENCE_HOSTS = {
    "api.github.com",
    "developer.apple.com",
    # Official vendor, distribution, and documentation domains referenced from
    # client source, tooling, and catalog attribution metadata.
    "ai.google.dev",
    "cdn.jsdelivr.net",
    "clawhub.ai",
    "cloud-images.ubuntu.com",
    "cloud.debian.org",
    "code.claude.com",
    "dl.rockylinux.org",
    "docs.github.com",
    "docs.microsoft.com",
    "docs.openclaw.ai",
    "download.opensuse.org",
    "flutter.dev",
    "forum.cursor.com",
    "github.com",
    "keepachangelog.com",
    "nodejs.org",
    "opencode.ai",
    "platform.kimi.ai",
    "pub.dev",
    "repo.almalinux.org",
    "semver.org",
    "static.rust-lang.org",
    "wiki.gnome.org",
    "www.apple.com",
    "www.kimi.com",
}
COLON = ":"
OPTIONAL_PORT_PATTERN = _join(["(?", COLON, r"\d+)?"])
REQUIRED_PORT_PATTERN = _join([COLON, r"\d+"])
DNS_LABEL_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN_HOST_PATTERN = _join([DNS_LABEL_PATTERN, r"(?:\.", DNS_LABEL_PATTERN, r")+"])
LOCAL_OR_DOMAIN_HOST_PATTERN = _join([r"(?:localhost|", DOMAIN_HOST_PATTERN, r")"])
PROTOCOL_HOST_PATTERN = _join([
    r"\b(?:https?|wss?|ssh|git)://",
    LOCAL_OR_DOMAIN_HOST_PATTERN,
    OPTIONAL_PORT_PATTERN,
])
KEY_VALUE_HOST_PATTERN = _join([
    r"(?i" + COLON + r"\b(?:host|hostname|domain|endpoint|url|origin|server|baseUrl|apiUrl|remote)\b\s*[:=]\s*[\"']?",
    r"(?:[A-Za-z][A-Za-z0-9+.-]*://)?",
    LOCAL_OR_DOMAIN_HOST_PATTERN,
    OPTIONAL_PORT_PATTERN,
    r")",
])
SSH_ENDPOINT_PATTERN = _join([r"\b[A-Za-z0-9._-]+@", LOCAL_OR_DOMAIN_HOST_PATTERN, REQUIRED_PORT_PATTERN, r"\b"])
SYSTEM_PATH_PATTERN = re.compile(
    r"(?<![:/A-Za-z0-9_.-])/(?:etc|opt|private/tmp|root|srv|tmp|usr/local|var)(?:/[^\s`'\"),;]*)?",
    re.IGNORECASE,
)
PRIVATE_KEY_BLOCK_PATTERN = re.compile(_join(["-----BEGIN ", r"(?:[A-Z0-9]+ )?PRIVATE KEY", "-----"]))
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:api[_-]?key|app[_-]?secret|auth[_-]?token|bearer[_-]?token|client[_-]?secret|connection[_-]?string|credential|db[_-]?password|password|passwd|private[_-]?key|refresh[_-]?token|secret|secret[_-]?key|service[_-]?token|signing[_-]?key|token)\b\s*[:=]\s*[\"']?[^\s\"'#]{16,}",
    re.IGNORECASE,
)
OPS_HOST_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:host|hostname|label|name|server|server_name)\b\s*[:=]\s*[\"']?[A-Za-z0-9][A-Za-z0-9._-]{2,}",
    re.IGNORECASE,
)
BUSINESS_INFO_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:arr|billing[_-]?account|commercial[_-]?account|contract[_-]?id|customer|customer[_-]?id|customer[_-]?name|deal|deal[_-]?id|invoice|invoice[_-]?id|lead|licensee|mrr|partner|prospect|revenue|sales[_-]?account)\b\s*[:=]\s*[\"']?[^\s\"'#,;}]{3,}",
    re.IGNORECASE,
)
PRODUCTION_METADATA_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:account[_-]?id|bucket|bucket[_-]?name|cluster|cluster[_-]?name|container[_-]?image|database|database[_-]?name|datacenter|db[_-]?name|droplet[_-]?id|image|instance|instance[_-]?id|kube[_-]?context|namespace|project[_-]?id|region|registry|resource[_-]?group|server[_-]?id|service[_-]?name|subscription[_-]?id|tenant[_-]?id|zone)\b\s*[:=]\s*[\"']?[^\s\"'#,;}]{3,}",
    re.IGNORECASE,
)
AUTH_HEADER_PATTERN = re.compile(
    r"\b(?:authorization|x-api-key|api-key)\b\s*[:=]\s*[\"']?(?:bearer\s+)?[A-Za-z0-9._~+/=-]{16,}",
    re.IGNORECASE,
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
CLOUD_ACCESS_KEY_PATTERN = re.compile(
    r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
DATABASE_CREDENTIAL_URL_PATTERN = re.compile(
    r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:[^@\s]+@",
    re.IGNORECASE,
)
OPS_ENDPOINT_URL_PATTERN = re.compile(r"\b(?:https?|wss?)://[^\s`'\"),;]+", re.IGNORECASE)


WINDOWS_DEVELOPER_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])[A-Za-z]:[\\/]"
    rf"(?:(?:Users[\\/]{ASCII_ACCOUNT_NAME_PATTERN}{PATH_COMPONENT_TERMINATOR_PATTERN})|"
    r"(?:(?:(?:[^\\/\s`'\")]+)[\\/])?"
    r"(?:dev(?:elopment|space)?|projects?|repos(?:itories)?|workspaces?)"
    r"(?:[\\/][^\s`'\")]+)+))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: re.Pattern[str]
    evidence_class: str
    should_report: Callable[[str, str], bool] | None = None


@dataclass(frozen=True)
class ProjectPolicy:
    policy_id: str
    description: str
    allowed_json_file_names: frozenset[str]
    allowed_json_path_patterns: tuple[str, ...]
    strict_json_config_prefixes: tuple[str, ...] = ()
    json_template_prefixes: tuple[str, ...] = ()
    shape_marker_keys: frozenset[str] = frozenset(CONFIG_SHAPE_MARKER_KEYS)


COMMON_JSON_PATH_PATTERNS = (
    r"docs/releases/plan\.json",
    r"schemas/release-plan\.schema\.json",
    r"github/rulesets/[^/]+\.json",
    r"modules/[^/]+/module\.json",
    r"(?:.*/)?tsconfig\.[a-z0-9_.-]+\.json",
    r"(?:.*/)?\.?mcp\.json",
    r"(?:.*/)?\.?codex-plugin/plugin\.json",
    r"(?:.*/)?\.?agents/plugins/marketplace\.json",
)
RELEASE_PLAN_KEYS = frozenset(
    {
        "$schema",
        "schemaVersion",
        "repository",
        "profile",
        "currentVersion",
        "versionSources",
        "changelog",
        "nextRelease",
        "releases",
        "components",
    }
)
MESHRIX_JSON_PATH_PATTERNS = (
    r"apps/console/appearance-presets/[^/]+\.json",
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json",
    r"docs/plans/.+\.json",
    r"docs/reports/[^/]+\.json",
    r"packages/[^/]+/manifest\.module\.json",
    r"packages/.+/module\.json",
    r"packages/agents/src/.+\.lifecycle\.json",
    r"packages/agents/src/agent-configs/.+\.json",
    r"packages/contracts/(?!client/).+\.schema\.json",
    r"packages/contracts/src/fixtures/.+\.json",
    r"packages/foundation/src/version-control/version-registry(?:\.schema)?\.json",
    r"packages/foundation/src/workflow/state-machine/definitions/.+\.json",
    r"packages/servicehub/src/registration/external-service\.example\.json",
    r"tests/objective-test-cases\.json",
    r"demo/[^/]+\.json",
    r"plugins/[^/]+\.schema\.json",
    r"plugins/.+/(?:adapter|plugin|configuration\.schema)\.json",
    r"plugins/.+/(?:capability|external-services|state-machines)/.+\.json",
    r"registry/[^/]+\.json",
    r"schemas/[^/]+\.json",
    r"tools/release/[^/]+\.lock\.json",
)
SKILL_TEMPLATE_JSON_PATH_PATTERNS = (
    r"config/[a-z0-9][a-z0-9-]*\.json",
    r"skills/catalog\.json",
    r"skills/skills\.lock\.json",
    r"skills/[^/]+/assets/[^/]+\.template\.json",
    r"workflows/catalog\.json",
)
SKILLS_CANONICAL_CONFIG_PATH_PATTERN = re.compile(r"config/[a-z0-9][a-z0-9-]*\.json")
SKILLS_CANONICAL_CONFIG_KEYS = frozenset(
    {
        "schemaVersion",
        "repositories",
        "canonicalEntrypoint",
        "forbiddenEntrypoints",
        "nestedEntrypointPolicy",
        "sharedRules",
    }
)
SKILLS_REPOSITORY_RECORD_KEYS = frozenset(
    {
        "directoryNames",
        "packageName",
        "skill",
        "title",
        "workspaceRoot",
        "overlay",
        "scanNested",
    }
)
SKILLS_NESTED_ENTRYPOINT_POLICY_KEYS = frozenset(
    {
        "inheritancePattern",
        "requireSharedRulesOrRootInheritance",
    }
)
LICOUP_JSON_PATH_PATTERNS = (
    r"vscode/settings\.json",
    r"apps/desktop/assets/agent-render-adapters/[^/]+\.json",
    r"apps/desktop/assets/appearance-presets/[^/]+\.json",
    r"apps/desktop/ios/runner/assets\.xcassets/.+/contents\.json",
    r"apps/desktop/macos/runner/assets\.xcassets/.+/contents\.json",
    r"apps/desktop/macos/runner/assets\.xcassets/.+/sourcemanifest\.json",
    r"apps/desktop/packaging\.modules\.json",
    r"apps/desktop/test/(?:fixtures|layout)/.+\.json",
    r"crates/licoup-native/resources/[^/]+\.json",
    r"crates/licoup-native/src/domain/targets/model_catalog/[^/]+\.json",
    r"docs/plans/manifest\.json",
    r"docs/plans/.+/checkpoints\.json",
    r"packages/contracts/client/.+\.schema\.json",
    r"packages/contracts/client/fixtures/.+\.json",
    r"plugins/[^/]+/mcp/server\.json",
    r"schemas/client_bridge/[^/]+\.json",
    r"tools/android-release-toolchain\.json",
    r"tools/client-[^/]+\.json",
    r"tools/licoup-[^/]+\.json",
    r"tools/scripts/[^/]+/probes\.json",
    r"tools/scripts/config/[^/]+\.json",
)
BADTOWER_JSON_PATH_PATTERNS = (
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json",
    r"config/[^/]+(?:\.template|\.schema)?\.json",
    r"schemas/.+\.json",
    r"registry/(?:core-host-contract|plugins)\.json",
    r"vendor/[^/]+\.json",
)
FABRIGENT_JSON_PATH_PATTERNS = (
    r"artifacts/[^/]+\.json",
    r"conformance/.+\.json",
    r"contracts/.+\.json",
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json",
    r"policies/.+\.json",
    r"protocols/(?:generated|schemas)/.+\.json",
    r"registry/.+\.json",
    r"schemas/.+\.json",
)
BADTOWER_CONFIG_SHAPE_MARKER_KEYS = frozenset(CONFIG_SHAPE_MARKER_KEYS | {"enabledProtocols"})
PROJECT_POLICIES = {
    "common": ProjectPolicy(
        policy_id="common",
        description="Common privacy gate for governed LicoLand public repositories.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS,
    ),
    "meshrix": ProjectPolicy(
        policy_id="meshrix",
        description="Meshrix platform, service, and plugin repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + MESHRIX_JSON_PATH_PATTERNS,
        strict_json_config_prefixes=STRICT_JSON_CONFIG_PREFIXES,
        json_template_prefixes=JSON_TEMPLATE_PREFIXES,
    ),
    "licoup": ProjectPolicy(
        policy_id="licoup",
        description="LicoUp client repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + LICOUP_JSON_PATH_PATTERNS,
    ),
    "badtower": ProjectPolicy(
        policy_id="badtower",
        description="BadTower untrusted communication-node repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + BADTOWER_JSON_PATH_PATTERNS,
        shape_marker_keys=BADTOWER_CONFIG_SHAPE_MARKER_KEYS,
    ),
    "fabrigent": ProjectPolicy(
        policy_id="fabrigent",
        description="Fabrigent federation protocol and policy-authority repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + FABRIGENT_JSON_PATH_PATTERNS,
    ),
    "website": ProjectPolicy(
        policy_id="website",
        description="Static website repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS,
    ),
    "skills": ProjectPolicy(
        policy_id="skills",
        description="Authoritative lico-dev skills repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + SKILL_TEMPLATE_JSON_PATH_PATTERNS,
    ),
}
REPOSITORY_POLICY_ALIASES = {
    ".github": "common",
    "Lico-Auditor": "common",
    "BadTower": "badtower",
    "Fabrigent": "fabrigent",
    "LicoArc-Plugins": "common",
    "LicoUp": "licoup",
    "Meshrix": "meshrix",
    "Meshrix-Plugins": "meshrix",
    "Meshrix-Services": "meshrix",
    "lico-auditor": "common",
    "lico-dev": "skills",
    "Lico-Dev": "skills",
    "lico.land": "website",
    "licoarc.com": "website",
    "licoland.com": "website",
    "licomesh.com": "website",
    "licoup.com": "website",
    "licoup.net": "website",
    "meshrix.io": "website",
}


def policy_for_profile(profile: str | None) -> ProjectPolicy:
    profile_id = (profile or "common").strip().lower()
    if profile_id in {"", "auto"}:
        profile_id = "common"
    return PROJECT_POLICIES.get(profile_id, PROJECT_POLICIES["common"])


def policy_profile_for_repo_name(repo_name: str) -> str:
    return REPOSITORY_POLICY_ALIASES.get(repo_name, "common")


def value_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def normalized_repo_path(path: str | Path) -> str:
    return Path(path).as_posix().lstrip("./").lower()


def path_parts(relative_path: str | Path) -> set[str]:
    return {part for part in normalized_repo_path(relative_path).split("/") if part}


def is_dependency_lockfile_path(relative_path: str | Path) -> bool:
    return Path(str(relative_path).replace("\\", "/")).name in DEPENDENCY_LOCKFILE_NAMES


def is_synthetic_test_or_fixture_path(relative_path: str | Path) -> bool:
    normalized = normalized_repo_path(relative_path)
    parts = path_parts(normalized)
    return (
        normalized.startswith(("tests/", "fixtures/"))
        or normalized.startswith("tools/server-scripts/verify-")
        or "/tests/" in normalized
        or "/fixtures/" in normalized
        or "test" in parts
        or "tests" in parts
        or "fixtures" in parts
    )


def should_scan_text_rule(rule_id: str, relative_path: str | Path) -> bool:
    if is_dependency_lockfile_path(relative_path):
        return rule_id in LOCKFILE_SECRET_RULES
    if is_synthetic_test_or_fixture_path(relative_path) and rule_id in SYNTHETIC_TEST_NOISE_RULES:
        return False
    return True


def file_policy_fingerprint(relative_path: str, rule_id: str, raw: bytes = b"") -> str:
    payload = relative_path.encode("utf-8", "replace") + b"\0" + rule_id.encode() + b"\0" + raw[:256]
    return hashlib.sha256(payload).hexdigest()[:16]


def is_strict_json_config_path(relative_path: str, policy: ProjectPolicy | None = None) -> bool:
    normalized = normalized_repo_path(relative_path)
    selected = policy or PROJECT_POLICIES["common"]
    return normalized.startswith(selected.strict_json_config_prefixes)


def is_allowed_json_config_path(relative_path: str, policy: ProjectPolicy | None = None) -> bool:
    selected = policy or PROJECT_POLICIES["common"]
    normalized = normalized_repo_path(relative_path)
    name = Path(normalized).name
    if name in selected.allowed_json_file_names:
        return True
    if any(re.fullmatch(pattern, normalized) for pattern in selected.allowed_json_path_patterns):
        return True
    if is_strict_json_config_path(normalized, selected):
        return True
    if normalized.startswith(selected.json_template_prefixes):
        return name.endswith((".json", ".template.json", ".config.json"))
    return False


def json_object_keys(data: object) -> set[str]:
    return {str(key) for key in data.keys()} if isinstance(data, dict) else set()


def user_record_score(record: object) -> int:
    if not isinstance(record, dict):
        return 0
    normalized_keys = {str(key).lower().replace("-", "_") for key in record}
    return len(normalized_keys & USER_RECORD_KEYS)


def looks_like_user_record_collection(data: object) -> bool:
    if isinstance(data, list):
        objects = [item for item in data[:20] if isinstance(item, dict)]
        return bool(objects) and any(user_record_score(item) >= 2 for item in objects)
    if isinstance(data, dict):
        normalized_keys = {str(key).lower().replace("-", "_") for key in data}
        if user_record_score(data) >= 3:
            return True
        for key, value in data.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in USER_RECORD_CONTAINER_KEYS and looks_like_user_record_collection(value):
                return True
        if normalized_keys & USER_RECORD_CONTAINER_KEYS:
            for value in data.values():
                if looks_like_user_record_collection(value):
                    return True
    return False


def is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(is_non_empty_string(item) for item in value)


def is_skills_repository_record(record: object) -> bool:
    if not isinstance(record, dict):
        return False
    keys = json_object_keys(record)
    if not keys <= SKILLS_REPOSITORY_RECORD_KEYS:
        return False
    string_fields = ("packageName", "title")
    if any(field in record and not is_non_empty_string(record[field]) for field in string_fields):
        return False
    if "skill" in record and record["skill"] is not None and not is_non_empty_string(record["skill"]):
        return False
    list_fields = ("directoryNames", "overlay")
    if any(field in record and not is_string_list(record[field]) for field in list_fields):
        return False
    boolean_fields = ("workspaceRoot", "scanNested")
    return not any(field in record and type(record[field]) is not bool for field in boolean_fields)


def is_skills_canonical_config_shape(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    keys = json_object_keys(data)
    if not {"schemaVersion", "repositories"} <= keys or not keys <= SKILLS_CANONICAL_CONFIG_KEYS:
        return False
    if type(data["schemaVersion"]) is not int or not isinstance(data["repositories"], dict):
        return False
    repositories = data["repositories"]
    if any(
        not re.fullmatch(r"[a-z0-9][a-z0-9-]*", str(name))
        or not is_skills_repository_record(record)
        for name, record in repositories.items()
    ):
        return False
    if "canonicalEntrypoint" in data and not is_non_empty_string(data["canonicalEntrypoint"]):
        return False
    if "forbiddenEntrypoints" in data and not is_string_list(data["forbiddenEntrypoints"]):
        return False
    if "nestedEntrypointPolicy" in data:
        nested_policy = data["nestedEntrypointPolicy"]
        if not isinstance(nested_policy, dict):
            return False
        if json_object_keys(nested_policy) != SKILLS_NESTED_ENTRYPOINT_POLICY_KEYS:
            return False
        if not is_non_empty_string(nested_policy["inheritancePattern"]):
            return False
        if type(nested_policy["requireSharedRulesOrRootInheritance"]) is not bool:
            return False
    if "sharedRules" in data:
        shared_rules = data["sharedRules"]
        if not isinstance(shared_rules, list):
            return False
        if any(
            not isinstance(rule, dict)
            or json_object_keys(rule) != {"id", "text"}
            or not is_non_empty_string(rule["id"])
            or not is_non_empty_string(rule["text"])
            for rule in shared_rules
        ):
            return False
    return True


def is_allowed_json_config_shape(relative_path: str, data: object, policy: ProjectPolicy | None = None) -> bool:
    selected = policy or PROJECT_POLICIES["common"]
    normalized = normalized_repo_path(relative_path)
    name = Path(normalized).name
    if selected.policy_id == "skills" and SKILLS_CANONICAL_CONFIG_PATH_PATTERN.fullmatch(normalized):
        return is_skills_canonical_config_shape(data)
    if not isinstance(data, dict):
        return isinstance(data, list) and normalized.startswith(JSON_LIST_SHAPE_PREFIXES)
    keys = json_object_keys(data)
    if not keys:
        return True
    if normalized == "docs/releases/plan.json":
        return (
            keys == RELEASE_PLAN_KEYS
            and data.get("schemaVersion") == 1
            and isinstance(data.get("repository"), str)
            and data.get("profile")
            in {
                "governance",
                "continuous-site",
                "inactive",
                "semver",
                "component-semver",
            }
        )
    if normalized == "schemas/release-plan.schema.json":
        return {"$schema", "$id", "type", "properties"} <= keys
    if normalized.startswith(JSON_LOCAL_OR_FIXTURE_SHAPE_PREFIXES):
        return True
    if name in {"mcp.json", ".mcp.json"}:
        return "mcpServers" in keys
    if selected.policy_id == "licoup":
        if normalized == "vscode/settings.json":
            return bool(keys)
        if re.fullmatch(r"plugins/[^/]+/mcp/server\.json", normalized):
            return "mcpServers" in keys
    if normalized.startswith("artifacts/") or normalized.startswith("vendor/"):
        return {"artifactVersion", "digest", "digestAlgorithm"} <= keys
    if normalized.startswith("conformance/"):
        return bool(keys)
    if normalized.startswith("contracts/") and name.endswith(".schema.json"):
        return {"$schema", "type"} <= keys
    if normalized.startswith("policies/"):
        return "policyVersion" in keys or bool(keys & selected.shape_marker_keys)
    if name == "package.json":
        return bool(keys & {"name", "version", "scripts", "dependencies", "devDependencies"})
    if name == "package-lock.json":
        return bool(keys & {"name", "lockfileVersion", "packages", "dependencies"})
    if name.startswith("tsconfig") and name.endswith(".json"):
        return bool(keys & {"compilerOptions", "extends", "files", "include", "references"})
    if re.fullmatch(r"modules/[^/]+/module\.json", normalized):
        return {"module_id", "module_type"} <= keys
    if normalized.startswith("tools/registry/schema/") and name.endswith(".schema.json"):
        return {"$schema", "type"} <= keys and "properties" in keys
    if normalized.startswith("tools/registry/"):
        return bool(keys & selected.shape_marker_keys)
    if is_strict_json_config_path(normalized, selected):
        return bool(keys & selected.shape_marker_keys)
    if normalized.startswith(selected.json_template_prefixes):
        return bool(keys & selected.shape_marker_keys)
    if any(re.fullmatch(pattern, normalized) for pattern in selected.allowed_json_path_patterns):
        return bool(keys & selected.shape_marker_keys)
    return False


def file_policy_violations(relative_path: str, raw: bytes, profile: str | None = None) -> list[tuple[str, str, str, str]]:
    policy = policy_for_profile(profile)
    normalized = normalized_repo_path(relative_path)
    suffix = Path(normalized).suffix.lower()
    findings: list[tuple[str, str, str, str]] = []

    def add(rule_id: str, message: str, evidence_class: str) -> None:
        findings.append((rule_id, message, evidence_class, file_policy_fingerprint(normalized, rule_id, raw)))

    if is_strict_json_config_path(normalized, policy) and suffix != ".json":
        if normalized in {item.lower() for item in ALLOWED_NON_JSON_CONFIG_PATHS}:
            return findings
        add(
            "config-directory-non-json-file",
            f"{policy.policy_id} fixed configuration directories may contain only schema-checked JSON files.",
            "data-file-policy",
        )
        return findings

    if suffix in BINARY_DATA_FILE_EXTENSIONS:
        add(
            "database-or-binary-data-file",
            "Database, spreadsheet, parquet, or other binary data files must not be committed.",
            "data-file-policy",
        )
        return findings

    if suffix in {".csv", ".tsv", ".sql", ".dump", ".jsonl", ".ndjson"}:
        add(
            "data-file-not-allowed",
            "Tabular, SQL dump, JSONL, or other data export files are denied unless replaced by an approved synthetic fixture format.",
            "data-file-policy",
        )
        return findings

    if suffix != ".json":
        return findings

    if not is_allowed_json_config_path(normalized, policy):
        add(
            "json-data-file-not-allowlisted",
            f"JSON files are denied by default under the {policy.policy_id} policy unless they are approved project configuration, registry, manifest, or template files.",
            "data-file-policy",
        )
        return findings

    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        add(
            "json-config-invalid",
            "Allowlisted JSON configuration files must parse as valid JSON.",
            "data-file-policy",
        )
        return findings

    if looks_like_user_record_collection(data):
        add(
            "user-record-data-shape",
            "User, customer, contact, account, or people record-shaped data must not be committed.",
            "user-data",
        )

    if not is_allowed_json_config_shape(normalized, data, policy):
        add(
            "json-config-shape-invalid",
            f"Allowlisted JSON files must match the expected {policy.policy_id} project configuration or registry object shape.",
            "data-file-policy",
        )

    return findings


def is_allowed_domain(host: str) -> bool:
    normalized = host.lower().strip("[] \t\r\n.,;:)")
    return normalized in ALLOWED_HOSTS or any(
        normalized == suffix or normalized.endswith(f".{suffix}")
        for suffix in ALLOWED_DOMAIN_SUFFIXES
    )


def host_from_endpoint(value: str) -> str:
    normalized = value.strip().strip("\"'")
    protocol_match = re.search(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#\s]+)", normalized)
    if protocol_match:
        return protocol_match.group(1)
    ssh_match = re.search(r"@([^:]+):\d+$", normalized)
    if ssh_match:
        return ssh_match.group(1)
    key_value_match = re.search(r"[:=]\s*[\"']?(.+)$", normalized)
    if key_value_match:
        value_part = key_value_match.group(1)
        protocol_match = re.search(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#\s]+)", value_part)
        if protocol_match:
            return protocol_match.group(1)
        host_match = re.search(LOCAL_OR_DOMAIN_HOST_PATTERN, value_part, re.IGNORECASE)
        if host_match:
            return host_match.group(0)
    return normalized


def value_has_explicit_endpoint_syntax(value: str) -> bool:
    return bool(re.search(r"^[A-Za-z][A-Za-z0-9+.-]*://", value.strip().strip("\"'")))


def is_dotted_code_identifier_host(host: str, original_value: str) -> bool:
    candidate = host.strip("[] \t\r\n.,;:)")
    if not candidate or value_has_explicit_endpoint_syntax(original_value):
        return False
    if any(char.isupper() for char in candidate):
        return True
    labels = candidate.lower().split(".")
    if len(labels) < 2:
        return False
    if labels[-1] in CODE_LIKE_HOST_FINAL_LABELS:
        return True
    return False


def is_reserved_synthetic_domain(host: str) -> bool:
    normalized = host.lower().strip("[] \t\r\n.,;:)")
    return (
        normalized.endswith((".test", ".invalid"))
        or normalized == "example.com"
        or normalized.startswith("example.")
        or normalized.endswith((".example", ".example.com", ".example.net", ".example.org"))
        or ".example." in normalized
    )


def is_public_reference_path(relative_path: str) -> bool:
    normalized = normalized_repo_path(relative_path)
    name = Path(normalized).name
    return (
        normalized.startswith(("docs/", "apps/console/", "apps/server/"))
        or bool(re.fullmatch(r"skills/[^/]+/references/.+", normalized))
        or normalized.startswith(("packages/contracts/", "tools/registry/schema/"))
        or name in {"readme.md", "readme.zh-cn.md", "changelog.md", "contributing.md", "license", "dockerfile"}
        or name in {"package.json", "pubspec.yaml", "analysis_options.yaml"}
        or name.endswith((".schema.json", ".svg", ".xml"))
        or "runtime-dependencies" in normalized
        or "environment-compatibility" in normalized
        or normalized.startswith(
            (
                "tools/release/",
                "templates/repository/tools/release/",
            )
        )
        or normalized.startswith(
            (
                "tools/server-scripts/mcp-",
                "tools/server-scripts/lib/mcp-",
                "tools/server-scripts/pack-offline-server.mjs",
            )
        )
    )


def is_public_package_reference_host(host: str, relative_path: str) -> bool:
    normalized = normalized_repo_path(relative_path)
    return host.lower() in PUBLIC_PACKAGE_HOSTS and (
        not normalized.startswith("deployment/")
        or is_public_reference_path(normalized)
        or "runtime-dependencies" in normalized
        or "environment-compatibility" in normalized
        or normalized.startswith("packages/foundation/config/deployment/")
        or normalized.startswith("tools/server-scripts/gerrit-local.mjs")
        or normalized.startswith("tools/server-scripts/setup-local-runtime.mjs")
    )


def is_public_integration_reference_host(host: str, relative_path: str) -> bool:
    normalized = normalized_repo_path(relative_path)
    if host.lower() not in PUBLIC_INTEGRATION_HOSTS:
        return False
    raw = relative_path.lower().replace("\\", "/")
    return any(
        marker in normalized
        for marker in (
            "external-service",
            "shared-cloud-drive",
            "oauth",
            "codex-oauth",
            "model-provider",
        )
    ) or normalized.startswith("docs/") or raw.startswith(".github/")


def is_public_reference_host(host: str, relative_path: str) -> bool:
    normalized = host.lower().strip("[] \t\r\n.,;:)")
    return (
        normalized in GLOBAL_STANDARD_REFERENCE_HOSTS
    ) or (
        normalized in PUBLIC_REFERENCE_HOSTS and is_public_reference_path(relative_path)
    ) or (
        normalized in PUBLIC_SOURCE_REFERENCE_HOSTS and not normalized_repo_path(relative_path).startswith("deployment/")
    ) or is_public_package_reference_host(normalized, relative_path) or is_public_integration_reference_host(
        normalized,
        relative_path,
    )


def is_local_development_domain(host: str, relative_path: str) -> bool:
    normalized = host.lower().strip("[] \t\r\n.,;:)")
    # Docker embedded DNS names (host.docker.internal and peers) resolve only
    # inside a developer container network, like .local mDNS names.
    is_local_name = normalized.endswith(".local") or normalized.endswith(".docker.internal")
    return is_local_name and (
        is_source_code_path(relative_path)
        or is_public_reference_path(relative_path)
        or normalized_repo_path(relative_path).startswith(("docs/", "tools/registry/schema/"))
    )


def is_local_tool_service_host(host: str, relative_path: str) -> bool:
    normalized = host.lower().strip("[] \t\r\n.,;:)")
    if normalized == "*":
        return True
    return normalized in {"lico-runtime-download-service"} and is_source_code_path(relative_path)


def is_public_github_pages_dns_path(relative_path: str) -> bool:
    return normalized_repo_path(relative_path) == "dns/cloudflare-github-pages.txt"


def is_non_loopback_ipv4(value: str, relative_path: str) -> bool:
    if relative_path.endswith(".svg"):
        return False
    if normalized_repo_path(relative_path) == "tools/config-scanner.mjs":
        return False
    if is_public_github_pages_dns_path(relative_path):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.version == 4
        and str(address) not in ALLOWED_IPV4_LITERALS
        and str(address) not in PROVIDER_METADATA_IPV4_LITERALS
    )


def is_non_loopback_ipv6(value: str, relative_path: str) -> bool:
    if is_public_github_pages_dns_path(relative_path):
        return False
    candidate = value.strip("[] \t\r\n.,;)")
    is_bracketed = value.strip().startswith("[") and value.strip().endswith("]")
    if candidate == "::" or (not is_bracketed and re.search(r"[A-Za-z]", candidate)):
        return False
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return address.version == 6 and str(address) != "::1"


def is_disallowed_domain(value: str, relative_path: str) -> bool:
    host = host_from_endpoint(value)
    # Numeric dotted tuples (dependency versions such as "2.5" or shorthand
    # loopback forms such as "127.1") are not hostnames; IPv4-shaped tuples
    # stay covered by the dedicated ip-literal rule.
    if not host or re.fullmatch(r"\d+(?:\.\d+)+", host):
        return False
    if is_dotted_code_identifier_host(host, value):
        return False
    if (
        is_reserved_synthetic_domain(host)
        or is_local_development_domain(host, relative_path)
        or is_public_reference_host(host, relative_path)
    ):
        return False
    return not is_allowed_domain(host)


def is_production_ssh_endpoint(value: str, relative_path: str) -> bool:
    host = host_from_endpoint(value)
    return not (
        is_allowed_domain(host)
        or is_reserved_synthetic_domain(host)
        or is_public_reference_host(host, relative_path)
    )


def is_public_placeholder_value(candidate: str) -> bool:
    normalized = candidate.strip().strip("\"'`.,;)}]")
    lowered = normalized.lower()
    if len(normalized) < 3:
        return True
    placeholder_words = {
        "changeme",
        "demo",
        "dummy",
        "example",
        "fake",
        "fixture",
        "mock",
        "placeholder",
        "redacted",
        "sample",
        "test",
    }
    common_values = {
        "false",
        "none",
        "null",
        "object",
        "string",
        "todo",
        "true",
        "unknown",
        "undefined",
    }
    code_expression_prefixes = (
        "config.",
        "context.",
        "ctx.",
        "env.",
        "input.",
        "options.",
        "params.",
        "process.",
        "props.",
        "request.",
        "response.",
        "state.",
        "this.",
    )
    if lowered in common_values:
        return True
    if lowered.startswith(("credential:", "secretref:", "tokenref:")):
        return True
    if "${" in lowered or lowered.startswith(("${", "$(", "%", "{", "{{", "<", "__", "your-", "your_")):
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", normalized):
        return True
    if lowered.startswith(code_expression_prefixes):
        return True
    if any(word in lowered for word in placeholder_words):
        return True
    return (
        "meshrix" in lowered
        or "licoup" in lowered
        or "badtower" in lowered
        or "fabrigent" in lowered
        or "lico-auditor" in lowered
        or is_allowed_domain(normalized)
    )


def is_operational_path(relative_path: str) -> bool:
    normalized = relative_path.lower().replace("\\", "/")
    parts = {part for part in normalized.split("/") if part}
    return (
        normalized.startswith(
            (
                ".github/workflows/",
                "deploy/",
                "deployment/",
                "infra/",
                "ops/",
                "scripts/",
                "tools/scripts/",
            )
        )
        or "/deploy/" in normalized
        or "/deployment/" in normalized
        or "/infra/" in normalized
        or "/ops/" in normalized
        or "/scripts/" in normalized
        or any(part.endswith("scripts") for part in parts)
    )


_AUDIT_ENGINE_FILES = frozenset(
    {
        "__init__.py",
        "cli.py",
        "models.py",
        "privacy_rules.py",
        "report.py",
        "scanner.py",
    }
)


def is_source_code_path(relative_path: str) -> bool:
    normalized = normalized_repo_path(relative_path)
    if normalized.startswith(
        ("apps/", "packages/", "crates/", "content/", "plugins/", "src/", "tools/", "lico_auditor/")
    ):
        return True
    parts = normalized.split("/")
    return (
        len(parts) == 2
        and parts[1] in _AUDIT_ENGINE_FILES
        and (parts[0].endswith("_audit") or parts[0].endswith("_auditor"))
    )


def is_system_or_deployment_path(value: str, relative_path: str) -> bool:
    if is_synthetic_test_or_fixture_path(relative_path):
        return False
    normalized = normalized_repo_path(relative_path)
    lowered_value = value.lower()
    if normalized in {"docker-compose.yml", "docker-compose.yaml"}:
        return False
    if normalized == "dockerfile" or normalized.endswith("/dockerfile"):
        return any(
            marker in lowered_value
            for marker in ("/" + "etc/ssh", "/" + "root/.ssh", "/" + "srv/")
        )
    if is_source_code_path(normalized):
        return False
    return True


def is_operational_endpoint_url(value: str, relative_path: str) -> bool:
    if not is_operational_path(relative_path):
        return False
    if "${" in value or "<" in value:
        return False
    host = host_from_endpoint(value)
    if (
        is_allowed_domain(host)
        or is_reserved_synthetic_domain(host)
        or is_public_reference_host(host, relative_path)
        or is_local_tool_service_host(host, relative_path)
    ):
        return False
    if re.fullmatch(LOCAL_OR_DOMAIN_HOST_PATTERN, host, re.IGNORECASE):
        return False
    if re.fullmatch(r"\d+(?:\.\d+){3}", host):
        return False
    return True


def is_sensitive_business_assignment(value: str, _relative_path: str) -> bool:
    candidate = _candidate_secret_value(value)
    return not is_public_placeholder_value(candidate)


def is_production_metadata_assignment(value: str, relative_path: str) -> bool:
    if not is_operational_path(relative_path):
        return False
    if "\n" in value or "\r" in value:
        return False
    normalized = relative_path.lower().replace("\\", "/")
    if normalized.startswith(("tests/", "fixtures/")) or "/tests/" in normalized or "/fixtures/" in normalized:
        return False
    candidate = _candidate_secret_value(value)
    if is_source_code_path(relative_path) and (
        is_public_placeholder_value(candidate)
        or looks_like_code_expression_value(candidate)
        or looks_like_governed_versioned_name(candidate)
    ):
        return False
    return not is_public_placeholder_value(candidate)


def is_deployment_provider_resource_id(_value: str, relative_path: str) -> bool:
    normalized = relative_path.lower().replace("\\", "/")
    return normalized.startswith("deployment/production/") or normalized.endswith("/vultr-ip-finder.ps1")


def is_cloud_server_provisioning_assignment(value: str, relative_path: str) -> bool:
    normalized_path = relative_path.lower().replace("\\", "/")
    if not normalized_path.endswith("/vultr-ip-finder.ps1"):
        return False
    candidate = _candidate_secret_value(value).strip().lower()
    if not candidate or candidate.startswith(("<", "{", "$", "%")):
        return False
    return "placeholder" not in candidate and "example" not in candidate


def _candidate_secret_value(value: str) -> str:
    match = re.search(r"[:=]\s*[\"']?(?:bearer\s+)?([^\s\"'#]+)", value, re.IGNORECASE)
    return match.group(1) if match else value


def _candidate_secret_key(value: str) -> str:
    match = re.search(r"\b([A-Za-z0-9_-]+)\b\s*[:=]", value)
    return match.group(1).lower().replace("-", "_") if match else ""


def is_secret_reference_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized.endswith(("ref", "refs", "reference", "reference_id"))


def looks_like_code_expression_value(candidate: str) -> bool:
    stripped = candidate.strip().strip("\"'`.,;)}]")
    if "${" in stripped:
        return True
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$?.]*", stripped):
        return True
    # Fully qualified path expressions (Rust/C++-style `module::Type`, with an
    # optional leading `&`, `*`, or `:` left over from assignment splitting)
    # are code references, not opaque literals.
    path_candidate = stripped.lstrip("&*:")
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(?:::[A-Za-z_$][A-Za-z0-9_$]*)*", path_candidate):
        return True
    if re.search(r"[(){}\[\]]", stripped):
        return True
    return bool(re.search(r"\b(?:await|new|return|async|function)\b", stripped))


# Governed version identifiers end in a lowercase kebab-case name with a
# numeric revision (for example a report or registry entry revision). Such
# revisioned names are version-registry identities, not credentials or
# deployment metadata.
GOVERNED_VERSIONED_NAME_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*-[0-9]+(?:\.[0-9]+)*")


def looks_like_governed_versioned_name(candidate: str) -> bool:
    stripped = candidate.strip().strip("\"'`.,;)}]")
    if len(stripped) < 3:
        return False
    return bool(GOVERNED_VERSIONED_NAME_PATTERN.fullmatch(stripped))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def secret_character_class_count(value: str) -> int:
    classes = [
        any(char.islower() for char in value),
        any(char.isupper() for char in value),
        any(char.isdigit() for char in value),
        any(not char.isalnum() for char in value),
    ]
    return sum(classes)


def looks_like_opaque_secret_literal(candidate: str) -> bool:
    stripped = candidate.strip().strip("\"'`.,;)}]")
    if len(stripped) < 20:
        return False
    return secret_character_class_count(stripped) >= 3 and shannon_entropy(stripped) >= 3.2


def is_non_placeholder_secret(value: str, relative_path: str) -> bool:
    if value.lower().startswith(("credential:", "secretref:", "tokenref:")):
        return False
    if not re.search(r"[:=]", value):
        return False
    key = _candidate_secret_key(value)
    if is_secret_reference_key(key):
        return False
    candidate = _candidate_secret_value(value).strip()
    lowered = candidate.lower()
    if len(candidate) < 16:
        return False
    if is_public_placeholder_value(candidate):
        return False
    placeholder_words = {
        "changeme",
        "dummy",
        "example",
        "fake",
        "fixture",
        "mock",
        "placeholder",
        "redacted",
        "sample",
        "test",
    }
    if any(word in lowered for word in placeholder_words):
        return False
    if candidate.startswith(("${", "$(", "%", "{", "{{")):
        return False
    if is_synthetic_test_or_fixture_path(relative_path) or is_source_code_path(relative_path):
        if (
            looks_like_code_expression_value(candidate)
            or looks_like_governed_versioned_name(candidate)
            or not looks_like_opaque_secret_literal(candidate)
        ):
            return False
    return True


RULES = [
    Rule(
        "ssh-public-key-material",
        "high-risk",
        "Committed SSH public key material is access metadata; use a placeholder in examples.",
        re.compile(r"\bssh-(?:ed25519|rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]{20,}={0,3}(?:\s+[^\r\n]*)?"),
        "access-material",
    ),
    Rule(
        "private-key-material",
        "high-risk",
        "Private key material must never be committed.",
        PRIVATE_KEY_BLOCK_PATTERN,
        "secret-material",
    ),
    Rule(
        "credential-url",
        "high-risk",
        "Connection URLs with embedded credentials must never be committed.",
        DATABASE_CREDENTIAL_URL_PATTERN,
        "secret-material",
    ),
    Rule(
        "auth-header-secret",
        "high-risk",
        "Authorization headers and API key headers must not contain committed secret values.",
        AUTH_HEADER_PATTERN,
        "secret-material",
        is_non_placeholder_secret,
    ),
    Rule(
        "jwt-token",
        "high-risk",
        "JWT-like bearer tokens must not be committed.",
        JWT_PATTERN,
        "secret-material",
    ),
    Rule(
        "cloud-access-token",
        "high-risk",
        "Cloud, repository, or chat access tokens must not be committed.",
        CLOUD_ACCESS_KEY_PATTERN,
        "secret-material",
    ),
    Rule(
        "secret-assignment",
        "high-risk",
        "Secret-like configuration assignments must use external secret references or redacted placeholders.",
        SECRET_ASSIGNMENT_PATTERN,
        "secret-material",
        is_non_placeholder_secret,
    ),
    Rule(
        "ip-literal",
        "high-risk",
        "IP literals are not allowed in public source; use localhost, 0.0.0.0, 127.0.0.1, or an allowed Meshrix domain.",
        re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        "network-location",
        is_non_loopback_ipv4,
    ),
    Rule(
        "ip-literal",
        "high-risk",
        "IP literals are not allowed in public source; use localhost for local loopback or an allowed Meshrix domain.",
        re.compile(r"(?<![A-Za-z0-9_.-])(?:\[[0-9a-f:.]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39})(?![A-Za-z0-9_.-])", re.IGNORECASE),
        "network-location",
        is_non_loopback_ipv6,
    ),
    Rule(
        "disallowed-domain",
        "high-risk",
        "Only localhost and official LicoLand product domains are allowed as committed host/domain endpoints.",
        re.compile(_join([PROTOCOL_HOST_PATTERN, "|", KEY_VALUE_HOST_PATTERN]), re.IGNORECASE),
        "network-location",
        is_disallowed_domain,
    ),
    Rule(
        "admin-ssh-endpoint",
        "high-risk",
        "Admin SSH endpoints are production access metadata.",
        re.compile(SSH_ENDPOINT_PATTERN, re.IGNORECASE),
        "admin-endpoint",
        is_production_ssh_endpoint,
    ),
    Rule(
        "operational-endpoint-url",
        "high-risk",
        "Operational script, deployment, or CI endpoint URLs must use localhost or an allowed LicoLand product domain.",
        OPS_ENDPOINT_URL_PATTERN,
        "network-location",
        is_operational_endpoint_url,
    ),
    Rule(
        "business-sensitive-assignment",
        "high-risk",
        "Customer, tenant, contract, revenue, or commercial account values must not be committed.",
        BUSINESS_INFO_ASSIGNMENT_PATTERN,
        "business-confidential",
        is_sensitive_business_assignment,
    ),
    Rule(
        "production-metadata-assignment",
        "high-risk",
        "Production deployment, cloud resource, or backend service metadata must not be committed.",
        PRODUCTION_METADATA_ASSIGNMENT_PATTERN,
        "business-confidential",
        is_production_metadata_assignment,
    ),
    Rule(
        "provider-resource-id",
        "high-risk",
        "Cloud/provider resource IDs must not be committed in deployment material.",
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
        "provider-resource-id",
        is_deployment_provider_resource_id,
    ),
    Rule(
        "cloud-server-provisioning-setting",
        "high-risk",
        "Cloud server provisioning host, label, or name defaults must not be committed.",
        OPS_HOST_ASSIGNMENT_PATTERN,
        "ops-metadata",
        is_cloud_server_provisioning_assignment,
    ),
    Rule(
        "system-or-deployment-path",
        "high-risk",
        "Absolute server, container, deployment, or developer toolchain paths must not be committed.",
        SYSTEM_PATH_PATTERN,
        "local-path",
        is_system_or_deployment_path,
    ),
    Rule(
        "developer-macos-home-path",
        "high-risk",
        "Developer macOS home paths must not be reachable in public history.",
        re.compile(
            re.escape(MACOS_HOME_PREFIX)
            + ASCII_ACCOUNT_NAME_PATTERN
            + PATH_COMPONENT_TERMINATOR_PATTERN
        ),
        "local-path",
    ),
    Rule(
        "developer-linux-home-path",
        "high-risk",
        "Developer Linux home paths must not be reachable in public history.",
        re.compile(
            re.escape(LINUX_HOME_PREFIX)
            + ASCII_ACCOUNT_NAME_PATTERN
            + PATH_COMPONENT_TERMINATOR_PATTERN
        ),
        "local-path",
    ),
    Rule(
        "developer-windows-workspace-path",
        "high-risk",
        "Developer Windows home or workspace paths must not be reachable in public history.",
        WINDOWS_DEVELOPER_PATH_PATTERN,
        "local-path",
    ),
]


def should_scan_file(path: Path, profile: str | None = None) -> bool:
    if any(part.lower() in IGNORED_DIR_NAMES for part in path.parts):
        return False
    if path.name in IGNORED_FILE_NAMES:
        return False
    policy = policy_for_profile(profile)
    if is_strict_json_config_path(path.as_posix(), policy):
        return True
    if path.suffix.lower() in DATA_FILE_EXTENSIONS:
        return True
    if path.name == "Dockerfile" or ".env" in path.name:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def iter_text_files(root: Path, profile: str | None = None) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and should_scan_file(path.relative_to(root), profile):
            yield path
