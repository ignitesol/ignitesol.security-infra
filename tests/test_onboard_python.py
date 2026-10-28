"""secinfra-onboard: uv.lock detection, unlocked-project warning, config render."""
from __future__ import annotations

from pathlib import Path

import yaml
from secinfra.onboard import (
    _render_security_config,
    detect_ecosystems,
    unlocked_python_projects,
)


def _write(root: Path, rel: str, content: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_uv_lock_alone_marks_the_repo_as_python(tmp_path: Path):
    _write(tmp_path, "uv.lock", "version = 1\n")

    assert detect_ecosystems(tmp_path) == ["python"]


def test_unlocked_projects_lists_only_dirs_without_a_governing_lock(tmp_path: Path):
    _write(tmp_path, "locked/pyproject.toml", '[project]\nname = "a"\n')
    _write(tmp_path, "locked/uv.lock", "version = 1\n")
    _write(tmp_path, "legacy/requirements.txt", "requests\n")

    assert unlocked_python_projects(tmp_path) == ["legacy"]


def test_repo_without_python_has_no_unlocked_projects(tmp_path: Path):
    _write(tmp_path, "package.json", "{}")

    assert unlocked_python_projects(tmp_path) == []


def test_multi_ecosystem_config_is_valid_yaml(tmp_path: Path):
    out = _render_security_config("a@example.invalid", ["python", "npm"], ["security"])

    data = yaml.safe_load(out)

    assert data["license"]["ecosystems"] == ["python", "npm"]
    assert data["paths"] == {"scan_root": "."}


def test_python_repos_get_the_commented_require_uv_lock_hint(tmp_path: Path):
    with_py = _render_security_config("a@example.invalid", ["python"], ["security"])
    without = _render_security_config("a@example.invalid", ["npm"], ["security"])

    assert "#   require_uv_lock: true" in with_py
    assert "require_uv_lock" not in without
    assert "python" not in yaml.safe_load(with_py)  # still opt-in, never default-on
