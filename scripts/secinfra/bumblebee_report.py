"""System 2 — notify job entry point.

Reads the artifact written by the scan job:
  results/bumblebee.ndjson

Builds a supply-chain exposure summary, renders email, sends via SES.

Usage:
    python -m secinfra.bumblebee_report --results-dir results/ --workspace .
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .common.config import RepoConfig
from .common.github import repo_name, run_url, sha_short
from .common.mailer import send
from .common.render import render_html, render_text


@dataclass
class Match:
    package: str
    version: str
    ecosystem: str
    campaign: str
    catalog_file: str
    detail: str = ""


def _parse_ndjson(path: Path) -> tuple[int, list[Match]]:
    """Return (component_count, matches)."""
    component_count = 0
    matches: list[Match] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        rec_type = record.get("type", "")
        if rec_type == "component":
            component_count += 1
        elif rec_type == "finding":
            matches.append(Match(
                package=record.get("name", ""),
                version=record.get("version", ""),
                ecosystem=record.get("ecosystem", ""),
                campaign=record.get("campaign", record.get("catalog", "")),
                catalog_file=record.get("catalog_file", ""),
                detail=record.get("detail", ""),
            ))
    return component_count, matches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="System 2 notify: bumblebee report")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    config = RepoConfig.load(args.workspace)
    security_cc = os.environ.get("SECINFRA_SECURITY_CC", "")
    cc = [security_cc] if security_cc else []

    ndjson_path = results_dir / "bumblebee.ndjson"
    if not ndjson_path.exists():
        print("No bumblebee results found; skipping email.", file=sys.stderr)
        return 0

    component_count, matches = _parse_ndjson(ndjson_path)

    ctx = {
        "repo": repo_name(),
        "sha": sha_short(),
        "run_url": run_url(),
        "component_count": component_count,
        "matches": matches,
        "match_count": len(matches),
        "has_matches": bool(matches),
    }

    subject = (
        f"[bumblebee] {repo_name()} — {len(matches)} exposure match(es) "
        f"({component_count} components scanned)"
    )
    html = render_html("bumblebee", **ctx)
    text = render_text("bumblebee", **ctx)

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
