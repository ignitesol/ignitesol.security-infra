"""Shared loading for license-tracker's normalized output.

results/licenses-current.json shape: {ecosystem: [{name, version, license}]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


def load_current(results_dir: Path) -> dict:
    path = results_dir / "licenses-current.json"
    if path.exists():
        return json.loads(path.read_text())
    return {}


@dataclass
class AppliedOverride:
    ecosystem: str
    name: str
    detected: str
    override: str


def apply_overrides(
    current: dict, overrides: dict[str, str]
) -> tuple[dict, list[AppliedOverride]]:
    """Replace the detected license for any dependency matching
    license.policy.overrides (keyed "ecosystem/name", case-insensitive).

    Overrides substitute the value used for policy evaluation and reporting
    outright — including for a non-unknown value the scanner simply got
    wrong — they don't add a bypass on top of it, so an override still gets
    checked against the deny list like any other detected license.
    """
    if not overrides:
        return current, []

    applied: list[AppliedOverride] = []
    result: dict[str, list[dict]] = {}
    for ecosystem, deps in current.items():
        new_deps = []
        for dep in deps:
            name = dep.get("name", "")
            key = f"{ecosystem}/{name}".lower()
            override = overrides.get(key)
            if override:
                applied.append(AppliedOverride(
                    ecosystem, name, dep.get("license", "") or "Unknown", override,
                ))
                dep = {**dep, "license": override}
            new_deps.append(dep)
        result[ecosystem] = new_deps
    return result, applied
