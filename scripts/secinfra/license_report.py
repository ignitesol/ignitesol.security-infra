"""System 3 — notify job entry point.

Reads artifacts written by the scan job:
  results/licenses-current.json   — {ecosystem: [{name, version, license, spdx_id}]}

Diffs against the committed manifest at:
  .security/dependency-manifest.json

Renders an email listing new dependencies + their licenses,
then commits the refreshed manifest.

Usage:
    python -m secinfra.license_report --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .common.config import RepoConfig
from .common.github import commit_manifest, repo_name, run_url, sha_short
from .common.mailer import send
from .common.render import render_html, render_text


@dataclass
class Dependency:
    name: str
    version: str
    license: str
    spdx_id: str
    ecosystem: str


def _load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


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
                    spdx_id=dep.get("spdx_id", ""),
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

    current = _load_json(results_dir / "licenses-current.json")
    manifest_path = ws / ".security" / "dependency-manifest.json"
    previous = _load_json(manifest_path)

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

    # Commit refreshed manifest (only if contents:write job succeeds sending)
    commit_manifest(manifest_path, current, workspace=str(ws))
    return 0


if __name__ == "__main__":
    sys.exit(main())
