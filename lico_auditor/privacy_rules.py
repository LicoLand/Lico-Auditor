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
}
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
GITHUB_CORE_REMOTE = _join(["https://", "github", ".com/LicoLand/LicoMesh.git"])
GITHUB_LICOARC_REMOTE = _join(["https://", "github", ".com/LicoLand/LicoArc.git"])
GITHUB_LICO_DEV_REMOTE = _join(["https://", "github", ".com/LicoLand/Lico-Dev.git"])
GITHUB_SITE_REMOTE = _join(["https://", "github", ".com/LicoLand/licomesh.com.git"])
GITHUB_ORG_PROFILE_REMOTE = _join(["https://", "github", ".com/LicoLand/.github.git"])
GITHUB_COMMUNITY_REMOTE = _join(["https://", "github", ".com/LicoLand/licomesh-community.git"])
AUDITED_GITHUB_REMOTES = {
    "LicoMesh": GITHUB_CORE_REMOTE,
    "LicoArc": GITHUB_LICOARC_REMOTE,
    "lico-dev": GITHUB_LICO_DEV_REMOTE,
    "Lico-Dev": GITHUB_LICO_DEV_REMOTE,
    "licomesh.com": GITHUB_SITE_REMOTE,
    ".github": GITHUB_ORG_PROFILE_REMOTE,
    "licomesh-community": GITHUB_COMMUNITY_REMOTE,
}
ALLOWED_HOSTS = {"localhost", "0.0.0.0", "127.0.0.1", "::1"}
ALLOWED_IPV4_LITERALS = {"0.0.0.0", "127.0.0.1"}
ALLOWED_DOMAIN_SUFFIXES = ("licomesh.com", "licomesh.app", "licoland.com")
CODE_LIKE_HOST_FINAL_LABELS = {
    "argv",
    "arraybuffer",
    "baseurl",
    "config",
    "createserver",
    "domain",
    "endpoint",
    "equal",
    "find",
    "host",
    "hostname",
    "includes",
    "json",
    "lock",
    "match",
    "metadata",
    "mjs",
    "origin",
    "payload",
    "platform",
    "setdefault",
    "sh",
    "servers",
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
    "astral.sh",
    "caddyserver.com",
    "dart.dev",
    "desktop.docker.com",
    "developer.android.com",
    "developer.apple.com",
    "csrc.nist.gov",
    "docs.langchain.com",
    "docs.microsoft.com",
    "downloads.digitalcorpora.org",
    "flutter.dev",
    "github.com",
    "img.shields.io",
    "json-schema.org",
    "keepachangelog.com",
    "learn.microsoft.com",
    "rfc-editor.org",
    "source.android.com",
    "specifications.freedesktop.org",
    "theupdateframework.github.io",
    "modelcontextprotocol.io",
    "nginx.org",
    "nodejs.org",
    "pub.dev",
    "raw.githubusercontent.com",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "schemas.android.com",
    "schemas.openxmlformats.org",
    "semver.org",
    "unofficial-builds.nodejs.org",
    "vuejs.org",
    "wiki.gnome.org",
    "www.apple.com",
    "www.conventionalcommits.org",
    "www.gnu.org",
    "www.microsoft.com",
    "www.python.org",
    "www.rust-lang.org",
    "www.rfc-editor.org",
    "www.w3.org",
}
GLOBAL_STANDARD_REFERENCE_HOSTS = {
    "json-schema.org",
    "schemas.android.com",
    "schemas.openxmlformats.org",
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
    "www.dropbox.com",
    "www.googleapis.com",
}
PUBLIC_SOURCE_REFERENCE_HOSTS = {
    "developer.apple.com",
    "github.com",
    "keepachangelog.com",
    "opencode.ai",
    "pub.dev",
    "semver.org",
    "www.apple.com",
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
    r"(?i:\b(?:host|hostname|domain|endpoint|url|origin|server|baseUrl|apiUrl|remote)\b\s*[:=]\s*[\"']?",
    r"(?:[A-Za-z][A-Za-z0-9+.-]*://)?",
    LOCAL_OR_DOMAIN_HOST_PATTERN,
    OPTIONAL_PORT_PATTERN,
    r")",
])
SSH_ENDPOINT_PATTERN = _join([r"\b[A-Za-z0-9._-]+@", LOCAL_OR_DOMAIN_HOST_PATTERN, REQUIRED_PORT_PATTERN, r"\b"])
SYSTEM_PATH_PATTERN = re.compile(
    r"(?<![:/A-Za-z0-9_.-])/(?:etc|home|opt|private/tmp|root|srv|tmp|usr/local|var)(?:/[^\s`'\"),;]*)?",
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
    r"(?:(?:Users[\\/][^\\/\s`'\")]+)|"
    r"(?:(?:[^\\/\s`'\")]+)[\\/])?"
    r"(?:dev(?:elopment|space)?|projects?|repos(?:itories)?|workspaces?))"
    r"(?:[\\/][^\s`'\")]+)+",
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
    r"modules/[^/]+/module\.json",
    r"(?:.*/)?tsconfig\.[a-z0-9_.-]+\.json",
)
PLATFORM_JSON_PATH_PATTERNS = (
    r"apps/console/appearance-presets/[^/]+\.json",
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json",
    r"docs/generated/[^/]+\.generated\.json",
    r"docs/plan/[^/]+\.json",
    r"docs/scenarios/[^/]+\.json",
    r"packages/[^/]+/manifest\.module\.json",
    r"packages/.+/module\.json",
    r"packages/agents/src/agent-configs/.+\.json",
    r"packages/contracts/(?!client/).+\.schema\.json",
    r"packages/foundation/src/version-control/version-registry(?:\.schema)?\.json",
    r"packages/foundation/src/workflow/state-machine/definitions/[^/]+\.json",
    r"packages/servicehub/src/registration/external-service\.example\.json",
    r"tests/objective-test-cases\.json",
)
SKILL_TEMPLATE_JSON_PATH_PATTERNS = (
    r"config/developer-intent\.json",
    r"skills/catalog\.json",
    r"skills/skills\.lock\.json",
    r"skills/[^/]+/assets/[^/]+\.template\.json",
    r"workflows/catalog\.json",
)
CLIENT_JSON_PATH_PATTERNS = (
    r"apps/desktop/assets/agent-render-adapters/[^/]+\.json",
    r"apps/desktop/assets/appearance-presets/[^/]+\.json",
    r"apps/desktop/ios/Runner/Assets\.xcassets/.+/Contents\.json",
    r"apps/desktop/macos/Runner/Assets\.xcassets/.+/Contents\.json",
    r"apps/desktop/macos/Runner/Assets\.xcassets/.+/SourceManifest\.json",
    r"apps/desktop/packaging\.modules\.json",
    r"apps/desktop/test/(?:fixtures|layout)/.+\.json",
    r"crates/lico-client-native/resources/[^/]+\.json",
    r"packages/contracts/client/.+\.schema\.json",
    r"packages/contracts/client/fixtures/.+\.json",
    r"tools/android-release-toolchain\.json",
    r"tools/client-[^/]+\.json",
    r"tools/scripts/config/[^/]+\.json",
)
PROJECT_POLICIES = {
    "common": ProjectPolicy(
        policy_id="common",
        description="Common privacy gate for governed LicoMesh and LicoArc public repositories.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS,
    ),
    "platform": ProjectPolicy(
        policy_id="platform",
        description="Main LicoMesh Core repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + PLATFORM_JSON_PATH_PATTERNS,
        strict_json_config_prefixes=STRICT_JSON_CONFIG_PREFIXES,
        json_template_prefixes=JSON_TEMPLATE_PREFIXES,
    ),
    "client": ProjectPolicy(
        policy_id="client",
        description="LicoArc client repository policy.",
        allowed_json_file_names=frozenset(ALLOWED_JSON_FILE_NAMES),
        allowed_json_path_patterns=COMMON_JSON_PATH_PATTERNS + CLIENT_JSON_PATH_PATTERNS,
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
    "LicoArc": "client",
    "LicoMesh": "platform",
    "lico-auditor": "common",
    "lico-dev": "skills",
    "Lico-Dev": "skills",
    "licomesh-community": "common",
    "licomesh.com": "website",
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


def is_allowed_json_config_shape(relative_path: str, data: object, policy: ProjectPolicy | None = None) -> bool:
    selected = policy or PROJECT_POLICIES["common"]
    normalized = normalized_repo_path(relative_path)
    name = Path(normalized).name
    if not isinstance(data, dict):
        return False
    keys = json_object_keys(data)
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
        or normalized.startswith(("tools/server-scripts/mcp-", "tools/server-scripts/pack-offline-server.mjs"))
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
    return any(
        marker in normalized
        for marker in (
            "external-service",
            "shared-cloud-drive",
            "oauth",
            "codex-oauth",
            "model-provider",
        )
    ) or normalized.startswith("docs/")


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
    return normalized.endswith(".local") and (
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
    return address.version == 4 and str(address) not in ALLOWED_IPV4_LITERALS


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
    if not host or re.fullmatch(r"\d+(?:\.\d+){3}", host):
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
    if lowered.startswith(code_expression_prefixes):
        return True
    if any(word in lowered for word in placeholder_words):
        return True
    return (
        "licomesh" in lowered
        or "licoarc" in lowered
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
        ("apps/", "packages/", "crates/", "content/", "src/", "tools/", "lico_auditor/")
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
    normalized = relative_path.lower().replace("\\", "/")
    if normalized.startswith(("tests/", "fixtures/")) or "/tests/" in normalized or "/fixtures/" in normalized:
        return False
    candidate = _candidate_secret_value(value)
    if is_source_code_path(relative_path) and (is_public_placeholder_value(candidate) or looks_like_code_expression_value(candidate)):
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
    if re.search(r"[(){}\[\]]", stripped):
        return True
    return bool(re.search(r"\b(?:await|new|return|async|function)\b", stripped))


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
        if looks_like_code_expression_value(candidate) or not looks_like_opaque_secret_literal(candidate):
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
        "IP literals are not allowed in public source; use localhost, 0.0.0.0, 127.0.0.1, or an allowed LicoMesh domain.",
        re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        "network-location",
        is_non_loopback_ipv4,
    ),
    Rule(
        "ip-literal",
        "high-risk",
        "IP literals are not allowed in public source; use localhost for local loopback or an allowed LicoMesh domain.",
        re.compile(r"(?<![A-Za-z0-9_.-])(?:\[[0-9a-f:.]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39})(?![A-Za-z0-9_.-])", re.IGNORECASE),
        "network-location",
        is_non_loopback_ipv6,
    ),
    Rule(
        "disallowed-domain",
        "high-risk",
        "Only localhost, licomesh.com, licomesh.app, licoland.com, and their subdomains are allowed as committed host/domain endpoints.",
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
        "Operational script, deployment, or CI endpoint URLs must use localhost or an allowed LicoMesh domain.",
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
        re.compile(re.escape(MACOS_HOME_PREFIX) + r"[^/\s`'\")]+(?:/[^\s`'\")]*)?"),
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
