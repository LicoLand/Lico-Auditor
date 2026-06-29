from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    message: str
    path: str = ""
    line: int = 0
    column: int = 0
    fingerprint: str = ""
    evidence_class: str = ""
    commit: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "fingerprint": self.fingerprint,
            "evidence_class": self.evidence_class,
            "commit": self.commit,
        }


@dataclass(frozen=True)
class AuditTarget:
    repo_root: Path
    project: str = "licolite"
    ref: str = "worktree"


@dataclass
class AuditReport:
    target: AuditTarget
    findings: list[Finding] = field(default_factory=list)
    report_version: str = "v0.1:licolite-audit-report"

    @property
    def failed(self) -> bool:
        return any(item.severity in {"high-risk", "error"} for item in self.findings)

    def summary(self) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for finding in self.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
        return {
            "status": "failed" if self.failed else "passed",
            "finding_count": len(self.findings),
            "by_severity": by_severity,
            "by_rule": by_rule,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report_version,
            "target": {
                "project": self.target.project,
                "repo": self.target.repo_root.name,
                "ref": self.target.ref,
            },
            "summary": self.summary(),
            "findings": [item.to_dict() for item in self.findings],
        }
