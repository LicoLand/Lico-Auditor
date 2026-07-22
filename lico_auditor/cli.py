from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .models import AuditReport, AuditTarget, Finding
from .privacy_rules import AUDITED_GITHUB_REMOTES, GITHUB_CORE_REMOTE
from .report import emit_findings, emit_report
from .scanner import remote_pull_refs, scan_history, scan_worktree

DEFAULT_REMOTE = GITHUB_CORE_REMOTE
ONLY_BRANCH = "only"


def git_text(repo_root: Path, args: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def current_commit(repo_root: Path) -> str:
    code, stdout, _stderr = git_text(repo_root, ["rev-parse", "HEAD"])
    return stdout.strip() if code == 0 else ""


def finding_identity(finding: Finding) -> tuple[object, ...]:
    return (
        finding.severity,
        finding.rule,
        finding.path,
        finding.line,
        finding.column,
        finding.fingerprint,
        finding.evidence_class,
        finding.commit,
    )


def collect_findings(
    repo_root: Path,
    *,
    include_history: bool = False,
    ref: str = "HEAD",
    max_commits: int = 0,
    profile: str | None = None,
) -> list[Finding]:
    findings = scan_worktree(repo_root, commit=current_commit(repo_root), profile=profile)
    if include_history:
        findings.extend(scan_history(repo_root, ref=ref, max_commits=max_commits, profile=profile))

    unique: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        unique.setdefault(finding_identity(finding), finding)
    return sorted(
        unique.values(),
        key=lambda item: (item.commit, item.path, item.line, item.column, item.rule),
    )


def command_gate(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        return emit_findings([Finding("error", "target-missing", "Target repo does not exist.")], fmt=args.format)
    findings = collect_findings(
        repo_root,
        include_history=args.history,
        ref=args.ref,
        max_commits=args.max_commits,
        profile=args.profile,
    )
    return emit_findings(findings, fmt=args.format)


def command_report(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    findings: list[Finding]
    if repo_root.exists():
        findings = collect_findings(
            repo_root,
            include_history=args.history,
            ref=args.ref,
            max_commits=args.max_commits,
            profile=args.profile,
        )
    else:
        findings = [Finding("error", "target-missing", "Target repo does not exist.")]
    report = AuditReport(AuditTarget(repo_root=repo_root, project=args.project, ref=args.ref), findings)
    return emit_report(report, fmt=args.format)


def command_github_surface(args: argparse.Namespace) -> int:
    findings: list[Finding] = []
    targets = AUDITED_GITHUB_REMOTES if args.all_targets else {"target": args.remote}
    for target_name, remote in targets.items():
        try:
            pull_refs = remote_pull_refs(remote)
        except RuntimeError:
            findings.append(
                Finding(
                    "error",
                    "remote-query-failed",
                    "Unable to query configured remote pull refs.",
                    path=target_name,
                )
            )
            continue
        if pull_refs:
            for item in pull_refs:
                sha, ref = item.split(maxsplit=1)
                findings.append(
                    Finding(
                        severity="high-risk",
                        rule="github-pull-ref-present",
                        message="GitHub pull request refs are reachable. For a freshly published clean repository this surface must be empty.",
                        path=f"{target_name}:{ref}",
                        fingerprint=sha[:16],
                        evidence_class="github-ref",
                    )
                )
    return emit_findings(findings, fmt=args.format)


def command_source_of_truth(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    branch = args.branch
    findings: list[Finding] = []
    if not repo_root.exists():
        return emit_findings([Finding("error", "target-missing", "Audit repository checkout does not exist.")], fmt=args.format)

    code, stdout, _stderr = git_text(repo_root, ["ls-remote", "--symref", args.remote, "HEAD"])
    if code != 0:
        findings.append(Finding("error", "audit-remote-unavailable", "Unable to inspect the configured audit remote."))
    else:
        default_ref = ""
        for line in stdout.splitlines():
            if line.startswith("ref:") and line.endswith("\tHEAD"):
                default_ref = line.split()[1]
                break
        expected_ref = f"refs/heads/{branch}"
        if default_ref != expected_ref:
            findings.append(
                Finding(
                    severity="high-risk",
                    rule="audit-default-branch-not-only",
                    message="Audit gate default branch must be the single only branch.",
                    path=default_ref or "<remote-head>",
                    evidence_class="source-of-truth",
                )
            )

    code, stdout, _stderr = git_text(repo_root, ["ls-remote", "--heads", args.remote])
    remote_heads: dict[str, str] = {}
    if code != 0:
        findings.append(Finding("error", "audit-remote-heads-unavailable", "Unable to inspect configured audit branches."))
    else:
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) == 2:
                remote_heads[parts[1]] = parts[0]
        expected_ref = f"refs/heads/{branch}"
        if args.enforce_remote_heads and set(remote_heads) != {expected_ref}:
            for ref in sorted(set(remote_heads) - {expected_ref}):
                findings.append(
                    Finding(
                        severity="high-risk",
                        rule="audit-extra-remote-branch",
                        message="Audit gate repository must not expose any remote branch except only.",
                        path=ref,
                        evidence_class="source-of-truth",
                    )
                )
            if expected_ref not in remote_heads:
                findings.append(
                    Finding(
                        severity="error",
                        rule="audit-only-branch-missing",
                        message="Audit gate repository must expose the only branch.",
                        path=expected_ref,
                        evidence_class="source-of-truth",
                    )
                )
        if args.require_current_head and expected_ref in remote_heads:
            local_head = current_commit(repo_root)
            if local_head != remote_heads[expected_ref]:
                findings.append(
                    Finding(
                        severity="high-risk",
                        rule="audit-not-running-latest-only",
                        message="Audit Action must run the latest HEAD of the only branch.",
                        path=expected_ref,
                        fingerprint=remote_heads[expected_ref][:16],
                        evidence_class="source-of-truth",
                    )
                )

    if args.enforce_local_branches:
        code, stdout, _stderr = git_text(repo_root, ["for-each-ref", "--format=%(refname)", "refs/heads"])
        if code != 0:
            findings.append(Finding("error", "audit-local-branches-unavailable", "Unable to inspect local audit branches."))
        else:
            local_refs = {line.strip() for line in stdout.splitlines() if line.strip()}
            expected_local = f"refs/heads/{branch}"
            if local_refs != {expected_local}:
                for ref in sorted(local_refs - {expected_local}):
                    findings.append(
                        Finding(
                            severity="high-risk",
                            rule="audit-extra-local-branch",
                            message="Local audit checkout must not keep branches other than only.",
                            path=ref,
                            evidence_class="source-of-truth",
                        )
                    )
                if expected_local not in local_refs:
                    findings.append(
                        Finding(
                            severity="error",
                            rule="audit-local-only-branch-missing",
                            message="Local audit checkout must keep the only branch.",
                            path=expected_local,
                            evidence_class="source-of-truth",
                        )
                    )

    return emit_findings(findings, fmt=args.format)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run external privacy audit gates for governed LicoMesh and LicoArc repositories."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="Run privacy-leak gate against a checked-out repository.")
    gate.add_argument("--repo", required=True, help="Target repository root.")
    gate.add_argument("--ref", default="HEAD", help="Git ref to scan when --history is enabled.")
    gate.add_argument("--history", action="store_true", help="Scan reachable git history for the target ref.")
    gate.add_argument("--max-commits", type=int, default=0, help="Limit history scan to the latest N commits; 0 scans all.")
    gate.add_argument(
        "--profile",
        choices=("auto", "common", "platform", "client", "website", "skills"),
        default="auto",
        help="Policy profile: auto, common, platform, client, website, or skills.",
    )
    gate.add_argument("--format", choices=("text", "json"), default="text")
    gate.set_defaults(func=command_gate)

    report = sub.add_parser("report", help="Emit a structured privacy audit report.")
    report.add_argument("--repo", required=True, help="Target repository root.")
    report.add_argument("--project", default="lico")
    report.add_argument("--ref", default="HEAD")
    report.add_argument("--history", action="store_true")
    report.add_argument("--max-commits", type=int, default=0)
    report.add_argument(
        "--profile",
        choices=("auto", "common", "platform", "client", "website", "skills"),
        default="auto",
        help="Policy profile: auto, common, platform, client, website, or skills.",
    )
    report.add_argument("--format", choices=("json", "text"), default="json")
    report.set_defaults(func=command_report)

    surface = sub.add_parser("github-surface", help="Check GitHub remote surfaces that should be absent in a clean public repo.")
    surface.add_argument("--remote", default=DEFAULT_REMOTE)
    surface.add_argument("--all-targets", action="store_true", help="Check all configured governed target repositories.")
    surface.add_argument("--format", choices=("text", "json"), default="text")
    surface.set_defaults(func=command_github_surface)

    source = sub.add_parser("source-of-truth", help="Fail unless the audit gate runs from the latest unique only branch.")
    source.add_argument("--repo", default=".", help="Audit repository checkout.")
    source.add_argument("--remote", default="origin", help="Git remote name or URL to inspect.")
    source.add_argument("--branch", default=ONLY_BRANCH, help="Required single source-of-truth branch.")
    source.add_argument("--require-current-head", action="store_true", help="Require local HEAD to equal remote only HEAD.")
    source.add_argument("--enforce-remote-heads", action="store_true", help="Require the remote to expose no branch except only.")
    source.add_argument("--enforce-local-branches", action="store_true", help="Require the local checkout to keep no branch except only.")
    source.add_argument("--format", choices=("text", "json"), default="text")
    source.set_defaults(func=command_source_of_truth)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"[lico-auditor] error: unexpected {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
