"""System 1 — merge-gate entry point.

Reads the same artifact the notify job reads:
  results/gitleaks.json
  results/semgrep.sarif
  results/trivy-sca.json
  results/trivy-iac.json

Evaluates the repo's configured severity threshold (systems.security.fail_on
in .security/config.yml) and exits non-zero when it's tripped. Gating is
opt-in: fail_on defaults to "none", so this job passes unconditionally until
a repo explicitly configures a threshold. Add this job's check
("security / Gate") as a required status check to actually block merges —
see docs/ADOPTION.md.

Gitleaks (secret) findings always fail the gate once fail_on is set to any
tier, regardless of how lenient that tier is — a checked-in credential is
categorically different from a graded SAST/SCA severity.

Usage:
    python -m secinfra.security_gate --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .common.config import RepoConfig
from .common.sarif import (
    Severity,
    count_by_severity,
    load_all_findings,
    meets_threshold,
)

_VALID_TIERS = {"critical", "high", "medium", "low"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="System 1 gate: fail the build on policy violations"
    )
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    config = RepoConfig.load(args.workspace)
    gate = config.systems.security

    findings = load_all_findings(results_dir)
    counts = count_by_severity(findings)
    print(f"Total findings: {len(findings)}")
    for sev, n in counts.items():
        print(f"  {sev}: {n}")

    if not gate.enabled:
        print("systems.security disabled; gate skipped.")
        return 0

    if gate.fail_on == "none":
        print(
            "systems.security.fail_on: none (default) — gating not opted in; "
            "gate passes."
        )
        return 0

    if gate.fail_on not in _VALID_TIERS:
        print(
            f"FAIL: invalid systems.security.fail_on value {gate.fail_on!r}; "
            f"expected one of {sorted(_VALID_TIERS)} or 'none'."
        )
        return 1

    secret_findings = [f for f in findings if f.tool == "gitleaks"]
    if secret_findings:
        print(
            f"FAIL: {len(secret_findings)} secret(s) detected by gitleaks — "
            "always blocks the gate once fail_on is set, regardless of tier."
        )
        for f in secret_findings:
            print(f"  - {f.location}: {f.title}")
        return 1

    threshold = Severity(gate.fail_on)
    tripped = [f for f in findings if meets_threshold(f.severity, threshold)]
    if tripped:
        print(f"FAIL: {len(tripped)} finding(s) at or above severity '{gate.fail_on}'.")
        for f in tripped[:20]:
            print(f"  - [{f.severity.value}] {f.tool} {f.location}: {f.title}")
        return 1

    print(f"PASS: no findings at or above severity '{gate.fail_on}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
