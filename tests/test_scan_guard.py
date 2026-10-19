"""Unit tests for the scanner-health guard (secinfra.scan_guard)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from secinfra import scan_guard
from secinfra.scan_guard import (
    ScanStatus,
    check_gitleaks,
    check_semgrep,
    load_health,
    main,
    record_status,
    semgrep_config_args,
    unhealthy_scanners,
)


def _sarif(rules: list[str], results: list[dict] | None = None) -> str:
    return json.dumps({
        "runs": [{
            "tool": {"driver": {"rules": [{"id": r} for r in rules]}},
            "results": results or [],
        }]
    })


class TestSemgrepConfigArgs:
    def test_splits_each_ruleset_into_its_own_config_flag(self):
        args = semgrep_config_args("p/default p/owasp-top-ten p/secrets")

        assert args == [
            "--config", "p/default",
            "--config", "p/owasp-top-ten",
            "--config", "p/secrets",
        ]

    def test_tolerates_extra_whitespace_and_newlines(self):
        args = semgrep_config_args("  p/default \n\tp/secrets  ")

        assert args == ["--config", "p/default", "--config", "p/secrets"]

    def test_single_ruleset(self):
        assert semgrep_config_args("p/ci") == ["--config", "p/ci"]

    def test_blank_input_yields_no_args(self):
        assert semgrep_config_args("   ") == []


class TestCheckGitleaks:
    def test_ok_when_exit_zero_and_report_is_empty_list(self, tmp_path: Path):
        report = tmp_path / "gitleaks.json"
        report.write_text("[]")

        status = check_gitleaks(0, report)

        assert status == ScanStatus("gitleaks", True)

    def test_ok_when_findings_present(self, tmp_path: Path):
        report = tmp_path / "gitleaks.json"
        report.write_text('[{"RuleID": "github-pat"}]')

        assert check_gitleaks(0, report).ok

    def test_fails_on_nonzero_exit_code_even_without_report(self, tmp_path: Path):
        # Reproduces the config-load failure: exit 1, no report written.
        status = check_gitleaks(1, tmp_path / "gitleaks.json")

        assert not status.ok
        assert "exited 1" in status.reason

    def test_fails_when_report_missing_despite_exit_zero(self, tmp_path: Path):
        status = check_gitleaks(0, tmp_path / "gitleaks.json")

        assert not status.ok
        assert "report" in status.reason

    def test_fails_when_report_is_not_a_json_list(self, tmp_path: Path):
        report = tmp_path / "gitleaks.json"
        report.write_text("not json")

        assert not check_gitleaks(0, report).ok


class TestCheckSemgrep:
    def test_ok_when_rules_loaded_and_no_results(self, tmp_path: Path):
        sarif = tmp_path / "semgrep.sarif"
        sarif.write_text(_sarif(["rule.a", "rule.b"]))

        assert check_semgrep(0, sarif) == ScanStatus("semgrep", True)

    def test_fails_when_sarif_lists_zero_rules(self, tmp_path: Path):
        # Reproduces the single-argument --config bug: empty SARIF, no error.
        sarif = tmp_path / "semgrep.sarif"
        sarif.write_text(_sarif([]))

        status = check_semgrep(0, sarif)

        assert not status.ok
        assert "0 rules" in status.reason

    def test_fails_on_nonzero_exit_code(self, tmp_path: Path):
        sarif = tmp_path / "semgrep.sarif"
        sarif.write_text(_sarif(["rule.a"]))

        status = check_semgrep(7, sarif)

        assert not status.ok
        assert "exited 7" in status.reason

    def test_fails_when_sarif_missing(self, tmp_path: Path):
        assert not check_semgrep(0, tmp_path / "semgrep.sarif").ok

    def test_fails_when_sarif_has_no_runs(self, tmp_path: Path):
        sarif = tmp_path / "semgrep.sarif"
        sarif.write_text('{"runs": []}')

        assert not check_semgrep(0, sarif).ok

    def test_fails_when_sarif_is_not_json(self, tmp_path: Path):
        sarif = tmp_path / "semgrep.sarif"
        sarif.write_text("<html>")

        assert not check_semgrep(0, sarif).ok


class TestHealthFile:
    def test_load_returns_none_when_absent(self, tmp_path: Path):
        assert load_health(tmp_path) is None

    def test_absent_health_file_fails_closed_for_every_guarded_scanner(
        self, tmp_path: Path
    ):
        broken = unhealthy_scanners(tmp_path)

        assert [s.scanner for s in broken] == list(scan_guard.GUARDED_SCANNERS)
        assert all("never reported" in s.reason for s in broken)

    def test_partial_health_file_flags_only_the_missing_scanner(
        self, tmp_path: Path
    ):
        record_status(tmp_path, ScanStatus("gitleaks", True))

        broken = unhealthy_scanners(tmp_path)

        assert [s.scanner for s in broken] == ["semgrep"]

    def test_record_accumulates_statuses_across_calls(self, tmp_path: Path):
        record_status(tmp_path, ScanStatus("gitleaks", True))
        record_status(tmp_path, ScanStatus("semgrep", False, "boom"))

        health = load_health(tmp_path)

        assert health == {
            "gitleaks": ScanStatus("gitleaks", True),
            "semgrep": ScanStatus("semgrep", False, "boom"),
        }
        assert unhealthy_scanners(tmp_path) == [ScanStatus("semgrep", False, "boom")]

    def test_record_overwrites_a_previous_status_for_the_same_scanner(
        self, tmp_path: Path
    ):
        record_status(tmp_path, ScanStatus("gitleaks", True))
        record_status(tmp_path, ScanStatus("semgrep", False, "boom"))
        record_status(tmp_path, ScanStatus("semgrep", True))

        assert unhealthy_scanners(tmp_path) == []

    def test_corrupt_health_file_is_reported_as_unhealthy_not_ignored(
        self, tmp_path: Path
    ):
        (tmp_path / scan_guard.HEALTH_FILE).write_text("{ nope")

        broken = unhealthy_scanners(tmp_path)

        assert len(broken) == 1
        assert "unreadable" in broken[0].reason


class TestCli:
    def test_semgrep_args_prints_one_argument_per_line(self, capsys):
        rc = main(["semgrep-args", "p/default p/secrets"])

        assert rc == 0
        assert capsys.readouterr().out.splitlines() == [
            "--config", "p/default", "--config", "p/secrets",
        ]

    def test_record_gitleaks_failure_exits_nonzero_and_annotates(
        self, tmp_path: Path, capsys
    ):
        rc = main([
            "record", "gitleaks", "--exit-code", "1",
            "--results-dir", str(tmp_path),
        ])

        assert rc == 1
        assert capsys.readouterr().out.startswith("::error")
        assert not load_health(tmp_path)["gitleaks"].ok

    def test_record_semgrep_success_exits_zero(self, tmp_path: Path):
        (tmp_path / "semgrep.sarif").write_text(_sarif(["r1"]))

        rc = main([
            "record", "semgrep", "--exit-code", "0",
            "--results-dir", str(tmp_path),
        ])

        assert rc == 0
        assert load_health(tmp_path)["semgrep"].ok

    def test_enforce_fails_when_a_scanner_never_reported(self, tmp_path: Path):
        record_status(tmp_path, ScanStatus("gitleaks", True))

        assert main(["enforce", "--results-dir", str(tmp_path)]) == 1

    def test_enforce_fails_when_a_scanner_is_unhealthy(self, tmp_path: Path):
        record_status(tmp_path, ScanStatus("gitleaks", True))
        record_status(tmp_path, ScanStatus("semgrep", False, "0 rules"))

        assert main(["enforce", "--results-dir", str(tmp_path)]) == 1

    def test_enforce_passes_when_all_guarded_scanners_are_healthy(
        self, tmp_path: Path
    ):
        record_status(tmp_path, ScanStatus("gitleaks", True))
        record_status(tmp_path, ScanStatus("semgrep", True))

        assert main(["enforce", "--results-dir", str(tmp_path)]) == 0

    def test_enforce_writes_github_step_summary(
        self, tmp_path: Path, monkeypatch
    ):
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        record_status(tmp_path, ScanStatus("gitleaks", False, "exited 1"))
        record_status(tmp_path, ScanStatus("semgrep", True))

        main(["enforce", "--results-dir", str(tmp_path)])

        assert "gitleaks" in summary.read_text()
        assert "exited 1" in summary.read_text()


def test_guard_is_stdlib_only():
    """The scan job runs this file with a bare `python3`; no third-party deps."""
    source = Path(scan_guard.__file__).read_text()

    for third_party in ("yaml", "jinja2", "boto3", "packaging"):
        assert f"import {third_party}" not in source
    assert "from ." not in source, "must not use package-relative imports"


@pytest.mark.parametrize("rules", ["", "   "])
def test_blank_rules_produce_no_args(rules: str):
    assert semgrep_config_args(rules) == []


def test_semgrep_args_cli_prints_nothing_for_blank_rules(capsys):
    assert main(["semgrep-args", "  "]) == 0
    assert capsys.readouterr().out == ""
