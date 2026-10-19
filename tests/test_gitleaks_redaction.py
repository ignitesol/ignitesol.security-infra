"""Secrets must never travel from a gitleaks report into emails or logs."""
from __future__ import annotations

import json
from pathlib import Path

from secinfra.common.render import render_html, render_text
from secinfra.common.sarif import Severity, load_all_findings, load_gitleaks_json

# Built by concatenation so this file does not itself look like a leaked token
# to secret scanners (including this repo's own push protection).
FAKE_TOKEN = "ghp_" + "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz"


def _unredacted_report(tmp_path: Path) -> Path:
    report = tmp_path / "gitleaks.json"
    report.write_text(json.dumps([{
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "app.py",
        "StartLine": 3,
        "Commit": "0123456789abcdef0123456789abcdef01234567",
        "Match": f'GITHUB_TOKEN = "{FAKE_TOKEN}"',
        "Secret": FAKE_TOKEN,
    }]))
    return report


def test_finding_message_never_contains_the_matched_secret(tmp_path: Path):
    findings = load_gitleaks_json(_unredacted_report(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert FAKE_TOKEN not in finding.message
    assert "GITHUB_TOKEN" not in finding.message
    assert "redacted" in finding.message.lower()


def test_finding_message_identifies_rule_and_short_commit(tmp_path: Path):
    finding = load_gitleaks_json(_unredacted_report(tmp_path))[0]

    assert "github-pat" in finding.message
    assert "01234567" in finding.message
    assert "0123456789abcdef0123" not in finding.message


def test_gitleaks_findings_keep_high_severity_and_location(tmp_path: Path):
    finding = load_gitleaks_json(_unredacted_report(tmp_path))[0]

    assert finding.severity is Severity.HIGH
    assert finding.location == "app.py:3"


def test_rendered_emails_do_not_leak_the_secret(tmp_path: Path):
    (tmp_path / "gitleaks.json").write_text(_unredacted_report(tmp_path).read_text())
    findings = load_all_findings(tmp_path)
    ctx = {
        "repo": "acme/widgets",
        "sha": "abc1234",
        "run_url": "https://example.invalid/run/1",
        "findings": findings,
        "counts": {"high": len(findings)},
        "total": len(findings),
        "has_findings": True,
        "scanner_failures": [],
    }

    html = render_html("security", **ctx)
    text = render_text("security", **ctx)

    assert FAKE_TOKEN not in html
    assert FAKE_TOKEN not in text
