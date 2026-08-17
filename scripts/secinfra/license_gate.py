"""System 3 — merge-gate entry point.

Reads the artifact written by the scan job:
  results/licenses-current.json   — {ecosystem: [{name, version, license}]}

Evaluates the repo's configured license policy (license.policy in
.security/config.yml) against every dependency CURRENTLY present — not just
newly-added ones (unlike license_report.py's diff-based email, which only
flags what changed since the last run). A repo that adopts this policy after
the fact should see its existing violations immediately, not just future
ones.

Gating is opt-in: license.policy.deny defaults to an empty list and
deny_unknown defaults to false, so this job passes unconditionally until a
repo explicitly configures a policy. Add this job's check
("license / Gate") as a required status check to actually block merges —
see docs/ADOPTION.md.

Usage:
    python -m secinfra.license_gate --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .common.config import RepoConfig
from .common.license import load_current

_UNKNOWN_LICENSES = {"", "unknown", "none", "noassertion"}


@dataclass
class Violation:
    ecosystem: str
    name: str
    version: str
    license: str
    reason: str


def _license_tokens(license_str: str) -> list[str]:
    """Split an SPDX-ish expression ("MIT OR Apache-2.0") into individual ids."""
    if not license_str:
        return []
    parts = re.split(r"\bOR\b|\bAND\b|[(),]", license_str, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]


def _matches_deny(token: str, deny_entry: str) -> bool:
    """Anchored prefix match so 'GPL' denies 'GPL-3.0-only' but not 'LGPL-2.1'."""
    token_l = token.strip().lower()
    deny_l = deny_entry.strip().lower()
    if not token_l or not deny_l:
        return False
    if token_l == deny_l:
        return True
    return re.match(rf"^{re.escape(deny_l)}([-+].*)?$", token_l) is not None


def _find_violations(current: dict, deny: list[str], deny_unknown: bool) -> list[Violation]:
    violations: list[Violation] = []
    for ecosystem, deps in current.items():
        for dep in deps:
            name = dep.get("name", "")
            version = dep.get("version", "")
            license_str = dep.get("license", "") or ""
            tokens = _license_tokens(license_str)

            if deny_unknown and (not tokens or all(t.lower() in _UNKNOWN_LICENSES for t in tokens)):
                violations.append(Violation(
                    ecosystem, name, version, license_str or "Unknown",
                    "license is unknown/missing",
                ))
                continue

            for token in tokens:
                hit = next((d for d in deny if _matches_deny(token, d)), None)
                if hit:
                    violations.append(Violation(
                        ecosystem, name, version, license_str,
                        f"matches denied license '{hit}'",
                    ))
                    break
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="System 3 gate: fail the build on license policy violations")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    config = RepoConfig.load(args.workspace)
    gate = config.systems.license
    policy = config.license.policy

    current = load_current(results_dir)
    total = sum(len(v) for v in current.values())
    print(f"Dependencies scanned: {total}")

    if not gate.enabled:
        print("systems.license disabled; gate skipped.")
        return 0

    if not policy.deny and not policy.deny_unknown:
        print("license.policy not configured (empty deny list, deny_unknown: false) — gate passes.")
        return 0

    violations = _find_violations(current, policy.deny, policy.deny_unknown)
    if violations:
        print(f"FAIL: {len(violations)} dependency(ies) violate license policy.")
        for v in violations[:30]:
            print(f"  - {v.ecosystem}/{v.name}@{v.version} [{v.license}] — {v.reason}")
        return 1

    print("PASS: no license policy violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
