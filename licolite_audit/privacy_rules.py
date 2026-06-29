from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


IGNORED_DIR_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
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


def _join(parts: Iterable[str]) -> str:
    return "".join(parts)


MACOS_HOME_PREFIX = _join(["/", "Users", "/"])
GITHUB_REMOTE = _join(["https://", "github", ".com/LicoLite/licolite.git"])
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
ALLOWED_DOMAIN_SUFFIXES = ("licolite.com", "licolite.app")
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
PRIVATE_KEY_BLOCK_PATTERN = re.compile(_join(["-----BEGIN ", r"(?:[A-Z0-9]+ )?PRIVATE KEY", "-----"]))
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:api[_-]?key|app[_-]?secret|auth[_-]?token|bearer[_-]?token|client[_-]?secret|connection[_-]?string|credential|db[_-]?password|password|passwd|private[_-]?key|refresh[_-]?token|secret|secret[_-]?key|service[_-]?token|signing[_-]?key|token)\b\s*[:=]\s*[\"']?[^\s\"'#]{16,}",
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


KNOWN_PRIVATE_MARKERS = [
    _join([MACOS_HOME_PREFIX, "un", "ka"]),
    _join(["T:", "/DevSpace"]),
    _join(["T:", "\\", "DevSpace"]),
    _join(["DevSpace", "/licolite"]),
    _join(["DevSpace", "\\", "licolite"]),
    _join(["com.", "un", "ka-malloc.lico"]),
    _join(["github.com/", "un", "ka/lico"]),
    _join(["github:", "un", "ka/"]),
    _join(["un", "ka/LicoLite"]),
    _join(["licolite", ".dev"]),
]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: re.Pattern[str]
    evidence_class: str
    should_report: Callable[[str, str], bool] | None = None


def value_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


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


def is_non_loopback_ipv4(value: str, relative_path: str) -> bool:
    if relative_path.endswith(".svg"):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and str(address) != "127.0.0.1"


def is_non_loopback_ipv6(value: str, _relative_path: str) -> bool:
    candidate = value.strip("[] \t\r\n.,;)")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return address.version == 6 and str(address) != "::1"


def is_disallowed_domain(value: str, _relative_path: str) -> bool:
    host = host_from_endpoint(value)
    if not host or re.fullmatch(r"\d+(?:\.\d+){3}", host):
        return False
    return not is_allowed_domain(host)


def is_production_ssh_endpoint(value: str, _relative_path: str) -> bool:
    return not is_allowed_domain(host_from_endpoint(value))


def is_deployment_provider_resource_id(_value: str, relative_path: str) -> bool:
    normalized = relative_path.lower().replace("\\", "/")
    return normalized.startswith("deployment/production/") or normalized.endswith("/vultr-ip-finder.ps1")


def _candidate_secret_value(value: str) -> str:
    match = re.search(r"[:=]\s*[\"']?(?:bearer\s+)?([^\s\"'#]+)", value, re.IGNORECASE)
    return match.group(1) if match else value


def is_non_placeholder_secret(value: str, _relative_path: str) -> bool:
    candidate = _candidate_secret_value(value).strip()
    lowered = candidate.lower()
    if len(candidate) < 16:
        return False
    placeholder_words = {
        "changeme",
        "dummy",
        "example",
        "fake",
        "placeholder",
        "redacted",
        "sample",
    }
    if any(word in lowered for word in placeholder_words):
        return False
    if candidate.startswith(("${", "$(", "%", "{", "{{")):
        return False
    return True


RULES = [
    Rule(
        "known-private-marker",
        "high-risk",
        "Known leaked local-path, old repository, or retired domain marker must not be reachable.",
        re.compile("|".join(re.escape(item) for item in KNOWN_PRIVATE_MARKERS)),
        "private-marker",
    ),
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
        "IP literals are not allowed in public source; use localhost for local loopback or an allowed LicoLite domain.",
        re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        "network-location",
        is_non_loopback_ipv4,
    ),
    Rule(
        "ip-literal",
        "high-risk",
        "IP literals are not allowed in public source; use localhost for local loopback or an allowed LicoLite domain.",
        re.compile(r"(?<![A-Za-z0-9_.-])(?:\[[0-9a-f:.]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39})(?![A-Za-z0-9_.-])", re.IGNORECASE),
        "network-location",
        is_non_loopback_ipv6,
    ),
    Rule(
        "disallowed-domain",
        "high-risk",
        "Only localhost, licolite.com, licolite.app, and their subdomains are allowed as committed host/domain endpoints.",
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
        "provider-resource-id",
        "high-risk",
        "Cloud/provider resource IDs must not be committed in deployment material.",
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
        "provider-resource-id",
        is_deployment_provider_resource_id,
    ),
    Rule(
        "developer-macos-home-path",
        "high-risk",
        "Developer macOS home paths must not be reachable in public history.",
        re.compile(re.escape(MACOS_HOME_PREFIX) + r"[^/\s`'\")]+(?:/[^\s`'\")]*)?"),
        "local-path",
    ),
    Rule(
        "developer-workspace-root",
        "high-risk",
        "Developer workspace roots must not be reachable in public history.",
        re.compile(r"\b(?:DevSpace[\\/]+licolite|[A-Za-z]:[\\/][^\s`'\")]*DevSpace[\\/]licolite)\b", re.IGNORECASE),
        "local-path",
    ),
]


def should_scan_file(path: Path) -> bool:
    if any(part in IGNORED_DIR_NAMES for part in path.parts):
        return False
    if path.name == "Dockerfile" or ".env" in path.name:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and should_scan_file(path.relative_to(root)):
            yield path
