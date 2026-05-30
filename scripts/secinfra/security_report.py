"""System 1 — notify job entry point.

Reads artifacts written by the scan job:
  results/gitleaks.json
  results/semgrep.sarif
  results/trivy-sca.json
  results/trivy-iac.json

Builds a unified summary, renders email, sends via SES.

Usage:
    python -m secinfra.security_report --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .common.config import RepoConfig
from .common.github import repo_name, run_url, sha_short
from .common.mailer import send
from .common.render import render_html, render_text
from .common.sarif import (
    Finding,
    count_by_severity,
    load_gitleaks_json,
    load_sarif,
    load_trivy_json,
    sort_findings,
)


def _load_findings(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []

    gitleaks = results_dir / "gitleaks.json"
    if gitleaks.exists() and gitleaks.stat().st_size > 2:
        findings.extend(load_gitleaks_json(gitleaks))

    semgrep = results_dir / "semgrep.sarif"
    if semgrep.exists():
        findings.extend(load_sarif(semgrep, "semgrep"))

    trivy_sca = results_dir / "trivy-sca.json"
    if trivy_sca.exists():
        findings.extend(load_trivy_json(trivy_sca))

    trivy_iac = results_dir / "trivy-iac.json"
    if trivy_iac.exists():
        findings.extend(load_trivy_json(trivy_iac))

    return sort_findings(findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="System 1 notify: security scan report")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    config = RepoConfig.load(args.workspace)
    security_cc = os.environ.get("SECINFRA_SECURITY_CC", "")
    cc = [security_cc] if security_cc else []

    findings = _load_findings(results_dir)
    counts = count_by_severity(findings)
    top_findings = findings[:20]

    ctx = {
        "repo": repo_name(),
        "sha": sha_short(),
        "run_url": run_url(),
        "findings": top_findings,
        "counts": counts,
        "total": len(findings),
        "has_findings": bool(findings),
    }

    subject = f"[security] {repo_name()} — {len(findings)} finding(s)"
    html = render_html("security", **ctx)
    text = render_text("security", **ctx)

    send(
        subject=subject,
        html_body=html,
        text_body=text,
        to=config.email.to,
        cc=cc,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
