from __future__ import annotations

import json
import os
import sys
from collections import Counter

from .models import AuditReport, Finding


DEFAULT_TEXT_FINDING_LIMIT = 200


def text_finding_limit() -> int:
    raw = os.environ.get("LICOLITE_AUDIT_TEXT_FINDING_LIMIT", str(DEFAULT_TEXT_FINDING_LIMIT))
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_TEXT_FINDING_LIMIT


def emit_findings(findings: list[Finding], *, fmt: str = "text") -> int:
    failed = any(item.severity in {"high-risk", "error"} for item in findings)
    if fmt == "json":
        print(json.dumps([item.to_dict() for item in findings], indent=2, sort_keys=True))
    elif findings:
        print("[licolite-audit] failed", file=sys.stderr)
        by_rule = Counter(item.rule for item in findings)
        by_severity = Counter(item.severity for item in findings)
        print(f"  findings={len(findings)} by_severity={dict(sorted(by_severity.items()))}", file=sys.stderr)
        print(f"  by_rule={dict(sorted(by_rule.items()))}", file=sys.stderr)
        limit = text_finding_limit()
        for item in findings[:limit]:
            location = f"{item.path}:{item.line}:{item.column}" if item.path else "<repository>"
            commit = f" commit={item.commit[:12]}" if item.commit else ""
            print(
                f"  - {item.severity} {location}{commit} "
                f"[{item.rule}] class={item.evidence_class} fingerprint={item.fingerprint}",
                file=sys.stderr,
            )
            print(f"    {item.message}", file=sys.stderr)
        if len(findings) > limit:
            print(f"  ... {len(findings) - limit} more finding(s) omitted from text output.", file=sys.stderr)
            print("  Use --format json for the complete structured finding list.", file=sys.stderr)
    else:
        print("[licolite-audit] passed")
    return 1 if failed else 0


def emit_report(report: AuditReport, *, fmt: str = "json") -> int:
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        return emit_findings(report.findings, fmt="text")
    return 1 if report.failed else 0
