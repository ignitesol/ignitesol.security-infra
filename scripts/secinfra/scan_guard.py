"""System 1 — scanner health guard.

Gitleaks and Semgrep used to fail in ways nothing noticed (a config that
would not load; a ruleset passed as one malformed argument), because the scan
steps are best-effort and swallow errors. A scanner that produced no findings
because it never ran looks identical to a clean scan. This module makes that
failure loud: after each scanner runs, `record` validates its exit code and
output and writes a verdict to results/scan-health.json; `enforce` fails the
scan job if any guarded scanner is unhealthy or never reported. The notify and
gate jobs read the same file so email and merge-gating can't report "clean"
for a scan that didn't happen. A missing entry counts as a failure.

Stdlib-only and free of package-relative imports on purpose: the credential-
less scan job runs this file directly from a sparse checkout, with no
`pip install`.

Usage (scan job):
    python3 scan_guard.py semgrep-args "p/default p/secrets"
    python3 scan_guard.py record gitleaks --exit-code $rc --results-dir results
    python3 scan_guard.py enforce --results-dir results
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

HEALTH_FILE = "scan-health.json"
GITLEAKS_REPORT = "gitleaks.json"
SEMGREP_SARIF = "semgrep.sarif"

# Scanners whose silent failure has already bitten us. Trivy is not guarded
# here: its steps fail visibly (no `|| true`), and an empty result is a
# legitimate outcome for it.
GUARDED_SCANNERS = ("gitleaks", "semgrep")


@dataclass(frozen=True)
class ScanStatus:
    scanner: str
    ok: bool
    reason: str = ""


def semgrep_config_args(rules: str) -> list[str]:
    """Turn a whitespace-separated ruleset list into repeated `--config` flags.

    Semgrep treats a single `--config "a b c"` as ONE config named "a b c",
    loads zero rules from it and (with `|| true`) exits quietly.
    """
    args: list[str] = []
    for ruleset in rules.split():
        args.extend(["--config", ruleset])
    return args


def check_gitleaks(exit_code: int, report: Path) -> ScanStatus:
    # The scan runs with `--exit-code 0`, so leaks never change the exit code:
    # any non-zero exit is a genuine error (e.g. config failed to load).
    if exit_code != 0:
        return ScanStatus(
            "gitleaks",
            False,
            f"gitleaks exited {exit_code} (config or runtime error; "
            "detected leaks do not affect the exit code)",
        )
    if not report.is_file():
        return ScanStatus("gitleaks", False, f"no report was written to {report}")
    try:
        parsed = json.loads(report.read_text())
    except (OSError, ValueError) as exc:
        return ScanStatus("gitleaks", False, f"report is not valid JSON: {exc}")
    if not isinstance(parsed, list):
        return ScanStatus("gitleaks", False, "report is not a JSON list")
    return ScanStatus("gitleaks", True)


def check_semgrep(exit_code: int, sarif: Path) -> ScanStatus:
    if exit_code != 0:
        return ScanStatus("semgrep", False, f"semgrep exited {exit_code}")
    if not sarif.is_file():
        return ScanStatus("semgrep", False, f"no SARIF was written to {sarif}")
    try:
        data = json.loads(sarif.read_text())
    except (OSError, ValueError) as exc:
        return ScanStatus("semgrep", False, f"SARIF is not valid JSON: {exc}")
    runs = data.get("runs") if isinstance(data, dict) else None
    if not runs:
        return ScanStatus("semgrep", False, "SARIF contains no runs")
    # driver.rules lists every rule semgrep loaded (not only those that
    # matched), so an empty list means no rules were loaded at all.
    loaded = sum(
        len(run.get("tool", {}).get("driver", {}).get("rules", []))
        for run in runs
    )
    if loaded == 0:
        return ScanStatus(
            "semgrep",
            False,
            "SARIF lists 0 rules loaded — the ruleset config was not "
            "resolved, so nothing was scanned",
        )
    return ScanStatus("semgrep", True)


def _status_from_json(scanner: str, raw: object) -> ScanStatus:
    if not isinstance(raw, dict):
        return ScanStatus(scanner, False, "malformed health entry")
    return ScanStatus(scanner, bool(raw.get("ok")), str(raw.get("reason", "")))


def load_health(results_dir: Path) -> dict[str, ScanStatus] | None:
    """Return recorded statuses, or None when no health file exists.

    Raises ValueError when the file exists but cannot be parsed.
    """
    path = results_dir / HEALTH_FILE
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path} is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path} is unreadable: not a JSON object")
    return {name: _status_from_json(name, entry) for name, entry in raw.items()}


def record_status(results_dir: Path, status: ScanStatus) -> None:
    try:
        existing = load_health(results_dir) or {}
    except ValueError:
        existing = {}
    merged = {**existing, status.scanner: status}
    payload = {
        name: {"ok": s.ok, "reason": s.reason} for name, s in merged.items()
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / HEALTH_FILE).write_text(json.dumps(payload, indent=2) + "\n")


def unhealthy_scanners(results_dir: Path) -> list[ScanStatus]:
    """Guarded scanners that failed or never reported (fail closed).

    A missing or partial health file counts as failure: the artifact is
    written in the same run by the same workflow, so absence means the
    scanner step died before recording, not "an older artifact".
    """
    try:
        health = load_health(results_dir) or {}
    except ValueError as exc:
        return [ScanStatus("scan-health", False, str(exc))]
    failed: list[ScanStatus] = []
    for name in GUARDED_SCANNERS:
        status = health.get(name)
        if status is None:
            failed.append(
                ScanStatus(name, False, "scanner never reported a status")
            )
        elif not status.ok:
            failed.append(status)
    failed.extend(
        s for name, s in health.items()
        if name not in GUARDED_SCANNERS and not s.ok
    )
    return failed


def _annotation(status: ScanStatus) -> str:
    message = status.reason.replace("%", "%25").replace("\n", "%0A")
    return f"::error title={status.scanner} did not run correctly::{message}"


def _write_step_summary(failed: list[ScanStatus]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path or not failed:
        return
    lines = ["### Scanner health check failed", ""]
    lines.extend(f"- **{s.scanner}**: {s.reason}" for s in failed)
    lines.append("")
    lines.append(
        "These scanners reported no findings only because they did not run "
        "correctly. The result is not a clean scan."
    )
    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _cmd_record(args: argparse.Namespace) -> int:
    results_dir = Path(args.results_dir)
    if args.scanner == "gitleaks":
        status = check_gitleaks(args.exit_code, results_dir / GITLEAKS_REPORT)
    else:
        status = check_semgrep(args.exit_code, results_dir / SEMGREP_SARIF)
    record_status(results_dir, status)
    if status.ok:
        print(f"{status.scanner}: healthy")
        return 0
    print(_annotation(status))
    return 1


def _cmd_enforce(args: argparse.Namespace) -> int:
    failed = unhealthy_scanners(Path(args.results_dir))
    if not failed:
        print("All guarded scanners reported healthy.")
        return 0
    for status in failed:
        print(_annotation(status))
    _write_step_summary(failed)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="System 1 scanner health guard")
    sub = parser.add_subparsers(dest="command", required=True)

    p_args = sub.add_parser(
        "semgrep-args", help="print --config flags, one argument per line"
    )
    p_args.add_argument("rules")

    p_record = sub.add_parser("record", help="validate a scanner run and record it")
    p_record.add_argument("scanner", choices=GUARDED_SCANNERS)
    p_record.add_argument("--exit-code", type=int, required=True)
    p_record.add_argument("--results-dir", default="results")

    p_enforce = sub.add_parser(
        "enforce", help="fail if any guarded scanner is unhealthy"
    )
    p_enforce.add_argument("--results-dir", default="results")

    args = parser.parse_args(argv)
    if args.command == "semgrep-args":
        config_args = semgrep_config_args(args.rules)
        if config_args:
            print("\n".join(config_args))
        return 0
    if args.command == "record":
        return _cmd_record(args)
    return _cmd_enforce(args)


if __name__ == "__main__":
    sys.exit(main())
