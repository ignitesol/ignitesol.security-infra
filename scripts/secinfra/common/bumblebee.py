"""Shared parsing for bumblebee's NDJSON scan output.

Bumblebee (perplexityai/bumblebee) NDJSON schema: every line carries a
`record_type` discriminator. Package observations use record_type
"package"; exposure-catalog matches use "finding". Each record's package
identity is `package_name`/`version`/`ecosystem`, and a finding names the
matched catalog via `catalog_name`/`catalog_id`. scan_summary and
diagnostic records are ignored here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Match:
    package: str
    version: str
    ecosystem: str
    campaign: str
    catalog_file: str
    detail: str = ""


def parse_ndjson(path: Path) -> tuple[int, list[Match]]:
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
        rec_type = record.get("record_type", "")
        if rec_type == "package":
            component_count += 1
        elif rec_type == "finding":
            catalog = record.get("catalog_name") or record.get("catalog_id", "")
            detail = record.get("evidence") or record.get("severity", "")
            matches.append(Match(
                package=record.get("package_name", ""),
                version=record.get("version", ""),
                ecosystem=record.get("ecosystem", ""),
                campaign=catalog,
                catalog_file=record.get("source_file", ""),
                detail=detail,
            ))
    return component_count, matches
