"""System 2 — merge-gate entry point.

Reads the artifact written by the scan job:
  results/bumblebee.ndjson

Evaluates the repo's configured policy (systems.bumblebee.fail_on in
.security/config.yml) and exits non-zero when it's tripped. Gating is
opt-in: fail_on defaults to "none", so this job passes unconditionally
until a repo explicitly sets fail_on: any. Add this job's check
("bumblebee / Gate") as a required status check to actually block merges —
see docs/ADOPTION.md.

Bumblebee's NDJSON exposure records carry no verified, documented severity
taxonomy (the upstream schema is undocumented and not vendored into this
repo), so the gate is boolean rather than tiered: any exposure-catalog
match fails the build when enabled. If a reliable severity/confidence field
is confirmed upstream later, this is the place to add tiers.

Usage:
    python -m secinfra.bumblebee_gate --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .common.bumblebee import count_packages_by_ecosystem, parse_ndjson
from .common.config import RepoConfig
from .common.python_projects import find_uv_lock_dirs, registry_package_count
from .common.scan_result import scan_job_failed

_VALID_TIERS = {"any"}


def _python_coverage_missing(
    workspace: Path, config: RepoConfig, ndjson_path: Path
) -> bool:
    """Locked third-party packages but zero PyPI records: the scan saw nothing."""
    lock_dirs = find_uv_lock_dirs(workspace, config.python.lock_exclude)
    if not any(registry_package_count(d) for d in lock_dirs):
        return False
    return count_packages_by_ecosystem(ndjson_path).get("pypi", 0) == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="System 2 gate: fail the build on exposure matches"
    )
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    workspace = Path(args.workspace or os.environ.get("GITHUB_WORKSPACE", "."))
    config = RepoConfig.load(workspace)
    gate = config.systems.bumblebee

    if gate.enabled and gate.fail_on == "any" and scan_job_failed():
        print(
            "FAIL: the scan job did not succeed, so there are no trustworthy "
            "results to gate on (see the Scan job's log)."
        )
        return 1

    ndjson_path = results_dir / "bumblebee.ndjson"
    if not ndjson_path.exists():
        print("No bumblebee results found; gate passes.")
        return 0

    component_count, matches = parse_ndjson(ndjson_path)
    print(f"Components scanned: {component_count}")
    print(f"Exposure matches: {len(matches)}")

    if not gate.enabled:
        print("systems.bumblebee disabled; gate skipped.")
        return 0

    if gate.fail_on == "none":
        print(
            "systems.bumblebee.fail_on: none (default) — gating not opted in; "
            "gate passes."
        )
        return 0

    if gate.fail_on not in _VALID_TIERS:
        print(
            f"FAIL: invalid systems.bumblebee.fail_on value {gate.fail_on!r}; "
            f"expected 'any' or 'none'."
        )
        return 1

    if _python_coverage_missing(workspace, config, ndjson_path):
        print(
            "FAIL: uv.lock lists third-party packages but the scan recorded no PyPI "
            "packages. Bumblebee read nothing from the Python environment, "
            "so a clean result would be meaningless."
        )
        return 1

    if matches:
        print(f"FAIL: {len(matches)} exposure match(es) against threat-intel catalogs.")
        for m in matches[:20]:
            print(f"  - {m.ecosystem}/{m.package}@{m.version} matched {m.campaign}")
        return 1

    print("PASS: no exposure matches.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
