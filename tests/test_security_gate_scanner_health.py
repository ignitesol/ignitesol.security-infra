"""The gate and the email must not call an unscanned repo clean."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from secinfra import security_gate
from secinfra.common.render import render_html, render_text
from secinfra.scan_guard import ScanStatus, record_status


def _workspace(tmp_path: Path, fail_on: str, name: str = "caller") -> Path:
    ws = tmp_path / name
    (ws / ".security").mkdir(parents=True)
    (ws / ".security" / "config.yml").write_text(
        f"email:\n  to: [dev@example.invalid]\nsystems:\n"
        f"  security:\n    fail_on: {fail_on}\n"
    )
    return ws


def _results(tmp_path: Path) -> Path:
    results = tmp_path / "results"
    results.mkdir()
    (results / "gitleaks.json").write_text("[]")
    return results


def _run_gate(results: Path, ws: Path) -> int:
    return security_gate.main(
        ["--results-dir", str(results), "--workspace", str(ws)]
    )


def test_gate_fails_closed_when_a_scanner_is_unhealthy_and_fail_on_is_set(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    results = _results(tmp_path)
    record_status(results, ScanStatus("gitleaks", False, "gitleaks exited 1"))
    record_status(results, ScanStatus("semgrep", True))

    rc = _run_gate(results, _workspace(tmp_path, "high"))

    assert rc == 1
    out = capsys.readouterr().out
    assert "gitleaks" in out
    assert "did not run" in out


def test_gate_still_passes_when_gating_is_not_opted_in(tmp_path: Path):
    results = _results(tmp_path)
    record_status(results, ScanStatus("semgrep", False, "0 rules"))

    assert _run_gate(results, _workspace(tmp_path, "none")) == 0


def test_gate_passes_when_scanners_healthy_and_no_findings(tmp_path: Path):
    results = _results(tmp_path)
    record_status(results, ScanStatus("gitleaks", True))
    record_status(results, ScanStatus("semgrep", True))

    assert _run_gate(results, _workspace(tmp_path, "high")) == 0


def test_gate_fails_closed_when_no_health_file_was_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """The scanner step died before recording (e.g. guard script missing)."""
    rc = _run_gate(_results(tmp_path), _workspace(tmp_path, "high"))

    assert rc == 1
    assert "never reported" in capsys.readouterr().out


def test_gate_fails_closed_when_only_one_scanner_reported(tmp_path: Path):
    results = _results(tmp_path)
    record_status(results, ScanStatus("gitleaks", True))

    assert _run_gate(results, _workspace(tmp_path, "high")) == 1


def test_gate_survives_a_truncated_report_from_a_failed_scanner(
    tmp_path: Path,
):
    results = _results(tmp_path)
    (results / "semgrep.sarif").write_text('{"runs": [{"tool"')
    record_status(results, ScanStatus("gitleaks", True))
    record_status(results, ScanStatus("semgrep", False, "semgrep exited 2"))

    # fail_on none: must not crash parsing the truncated SARIF.
    assert _run_gate(results, _workspace(tmp_path, "none")) == 0
    # fail_on set: fails for the scanner, not with a JSON traceback.
    assert _run_gate(results, _workspace(tmp_path, "high", "strict")) == 1


def test_secret_findings_still_fail_the_gate(tmp_path: Path):
    results = _results(tmp_path)
    (results / "gitleaks.json").write_text(json.dumps([{
        "RuleID": "github-pat", "Description": "token",
        "File": "a.py", "StartLine": 1, "Commit": "", "Match": "REDACTED",
    }]))
    record_status(results, ScanStatus("gitleaks", True))
    record_status(results, ScanStatus("semgrep", True))

    assert _run_gate(results, _workspace(tmp_path, "critical")) == 1


@pytest.mark.parametrize("renderer", [render_html, render_text])
def test_email_warns_instead_of_claiming_a_clean_scan(renderer):
    out = renderer(
        "security",
        repo="acme/widgets", sha="abc1234", run_url="https://example.invalid",
        findings=[], counts={}, total=0, has_findings=False,
        scanner_failures=[ScanStatus("semgrep", False, "SARIF lists 0 rules")],
    )

    assert "semgrep" in out
    assert "SARIF lists 0 rules" in out
    assert "clean scan" not in out.lower()


@pytest.mark.parametrize("renderer", [render_html, render_text])
def test_email_still_says_clean_when_scanners_are_healthy(renderer):
    out = renderer(
        "security",
        repo="acme/widgets", sha="abc1234", run_url="https://example.invalid",
        findings=[], counts={}, total=0, has_findings=False,
        scanner_failures=[],
    )

    assert "clean scan" in out.lower()


def _capture_report(
    monkeypatch: pytest.MonkeyPatch, results: Path, ws: Path
) -> dict:
    from secinfra import security_report

    sent: dict = {}
    monkeypatch.setattr(security_report, "send", lambda **kw: sent.update(kw))
    assert security_report.main(
        ["--results-dir", str(results), "--workspace", str(ws)]
    ) == 0
    return sent


def test_report_subject_and_body_flag_a_failed_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    results = _results(tmp_path)
    record_status(results, ScanStatus("gitleaks", False, "gitleaks exited 1"))
    record_status(results, ScanStatus("semgrep", True))

    sent = _capture_report(monkeypatch, results, _workspace(tmp_path, "none"))

    assert sent["subject"].endswith("SCANNER FAILED: gitleaks")
    assert "gitleaks exited 1" in sent["text_body"]
    assert "gitleaks exited 1" in sent["html_body"]


def test_report_subject_is_unchanged_when_scanners_are_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    results = _results(tmp_path)
    record_status(results, ScanStatus("gitleaks", True))
    record_status(results, ScanStatus("semgrep", True))

    sent = _capture_report(monkeypatch, results, _workspace(tmp_path, "none"))

    assert "SCANNER FAILED" not in sent["subject"]
    assert "clean scan" in sent["text_body"].lower()


def test_report_is_still_sent_when_a_failed_scanner_left_a_truncated_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    results = _results(tmp_path)
    (results / "gitleaks.json").write_text('[{"RuleID": "gith')
    record_status(results, ScanStatus("gitleaks", False, "gitleaks exited 1"))
    record_status(results, ScanStatus("semgrep", True))

    sent = _capture_report(monkeypatch, results, _workspace(tmp_path, "none"))

    assert sent["subject"].endswith("SCANNER FAILED: gitleaks")
