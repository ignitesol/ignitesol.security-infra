"""System 3 — notify job entry point.

Reads artifacts written by the scan job:
  results/licenses-current.json   — {ecosystem: [{name, version, license}]}

Diffs against the per-repo manifest persisted on the dedicated state branch
(secinfra/manifests by default, override via SECINFRA_STATE_BRANCH), keyed by
the source branch name:
  manifests/<source-branch>.json

Renders an email listing new dependencies + their licenses,
then persists the refreshed manifest back to the state branch via git plumbing
(no working-tree or default-branch writes — survives PR-required protection).

Usage:
    python -m secinfra.license_report --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .common.config import RepoConfig
from .common.github import (
    read_state_manifest,
    repo_name,
    run_url,
    sha_short,
    write_state_manifest,
)
from .common.license import apply_overrides, load_current
from .common.mailer import send
from .common.render import render_html, render_text


def _manifest_file() -> str:
    """State-branch path for this repo's manifest, keyed by source branch."""
    ref = os.environ.get("GITHUB_REF_NAME", "") or "default"
    safe = ref.replace("/", "-")
    return f"manifests/{safe}.json"


@dataclass
class Dependency:
    name: str
    version: str
    license: str
    ecosystem: str


def _flatten(manifest: dict) -> set[tuple[str, str, str]]:
    """Return set of (ecosystem, name, version) from the manifest."""
    result = set()
    for ecosystem, deps in manifest.items():
        for dep in deps:
            result.add((ecosystem, dep.get("name", ""), dep.get("version", "")))
    return result


def _diff(current: dict, previous: dict) -> list[Dependency]:
    prev_keys = _flatten(previous)
    added = []
    for ecosystem, deps in current.items():
        for dep in deps:
            key = (ecosystem, dep.get("name", ""), dep.get("version", ""))
            if key not in prev_keys:
                added.append(Dependency(
                    name=dep.get("name", ""),
                    version=dep.get("version", ""),
                    license=dep.get("license", "Unknown"),
                    ecosystem=ecosystem,
                ))
    added.sort(key=lambda d: (d.ecosystem, d.name))
    return added


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="System 3 notify: license/dep report")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    ws = Path(args.workspace or os.environ.get("GITHUB_WORKSPACE", "."))
    results_dir = Path(args.results_dir)
    config = RepoConfig.load(ws)
    security_cc = os.environ.get("SECINFRA_SECURITY_CC", "")
    cc = [security_cc] if security_cc else []

    current = load_current(results_dir)
    current, applied_overrides = apply_overrides(
        current, config.license.policy.overrides
    )
    for o in applied_overrides:
        print(f"  override: {o.ecosystem}/{o.name} [{o.detected}] -> [{o.override}]")
    manifest_file = _manifest_file()
    previous = read_state_manifest(manifest_file, workspace=str(ws))

    added = _diff(current, previous)

    by_ecosystem: dict[str, list[Dependency]] = {}
    for dep in added:
        by_ecosystem.setdefault(dep.ecosystem, []).append(dep)

    total_current = sum(len(v) for v in current.values())

    ctx = {
        "repo": repo_name(),
        "sha": sha_short(),
        "run_url": run_url(),
        "added": added,
        "added_count": len(added),
        "by_ecosystem": by_ecosystem,
        "total_current": total_current,
        "has_added": bool(added),
    }

    subject = f"[licenses] {repo_name()} — {len(added)} new dep(s) since last run"
    html = render_html("license", **ctx)
    text = render_text("license", **ctx)

    send(
        subject=subject,
        html_body=html,
        text_body=text,
        to=config.email.to,
        cc=cc,
    )

    # Persist refreshed manifest to the dedicated state branch (after send).
    write_state_manifest(
        manifest_file,
        current,
        workspace=str(ws),
        message=(
            f"chore(secinfra): update {manifest_file} for "
            f"{repo_name()} @ {sha_short()}"
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
