"""Shared loading for license-tracker's normalized output.

results/licenses-current.json shape: {ecosystem: [{name, version, license, spdx_id}]}
"""
from __future__ import annotations

import json
from pathlib import Path


def load_current(results_dir: Path) -> dict:
    path = results_dir / "licenses-current.json"
    if path.exists():
        return json.loads(path.read_text())
    return {}
