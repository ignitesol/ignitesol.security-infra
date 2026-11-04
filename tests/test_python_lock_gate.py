"""The uv.lock gate must fail any Python project that isn't locked with uv."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from secinfra import python_lock_gate
from secinfra.common.config import RepoConfig
from secinfra.python_lock_gate import find_violations

PYPROJECT = (
    '[project]\nname = "{name}"\nversion = "0.1.0"\n'
    'requires-python = ">=3.11"\n'
)
LOCK = (
    'version = 1\nrevision = 3\n\n[[package]]\n'
    'name = "{name}"\nversion = "0.1.0"\n'
)


def _fresh(_: Path) -> None:
    return None


def _stale(_: Path) -> str:
    return "needs update"


def _write(root: Path, rel: str, content: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _uv_project(root: Path, rel: str = ".", name: str = "demo") -> None:
    prefix = "" if rel == "." else f"{rel}/"
    _write(root, f"{prefix}pyproject.toml", PYPROJECT.format(name=name))
    _write(root, f"{prefix}uv.lock", LOCK.format(name=name))


def _codes(violations) -> list[str]:
    return [v.code for v in violations]


class TestDiscovery:
    def test_repo_without_python_manifests_passes(self, tmp_path: Path):
        _write(tmp_path, "package.json", "{}")
        _write(tmp_path, "src/app.js", "")

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_tool_only_pyproject_is_not_a_project(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", "[tool.ruff]\nline-length = 100\n")

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_virtualenv_and_node_modules_are_skipped(self, tmp_path: Path):
        _write(tmp_path, "node_modules/x/requirements.txt", "requests\n")
        _write(tmp_path, ".venv/requirements.txt", "requests\n")
        _write(tmp_path, "custom_env/pyvenv.cfg", "")
        _write(tmp_path, "custom_env/requirements.txt", "requests\n")

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_excluded_path_is_ignored(self, tmp_path: Path):
        _write(tmp_path, "tests/fixtures/old/requirements.txt", "requests\n")

        violations = find_violations(
            tmp_path, ["tests/fixtures"], check_fresh=_fresh
        )

        assert violations == []


class TestMissingLock:
    def test_requirements_only_project_fails(self, tmp_path: Path):
        _write(tmp_path, "requirements.txt", "requests==2.32.0\n")

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert _codes(violations) == ["missing-uv-lock"]
        assert "not a lockfile" in violations[0].reason

    def test_pyproject_without_uv_lock_fails(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", PYPROJECT.format(name="demo"))

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "missing-uv-lock"
        ]

    def test_poetry_project_fails_and_names_poetry(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", '[tool.poetry]\nname = "demo"\n')
        _write(tmp_path, "poetry.lock", "")

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert _codes(violations) == ["missing-uv-lock"]
        assert "poetry" in violations[0].reason

    def test_pipenv_project_fails_and_names_pipenv(self, tmp_path: Path):
        _write(tmp_path, "Pipfile", "[packages]\n")
        _write(tmp_path, "Pipfile.lock", "{}")

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert _codes(violations) == ["missing-uv-lock"]
        assert "pipenv" in violations[0].reason

    def test_each_unlocked_subproject_is_reported(self, tmp_path: Path):
        _uv_project(tmp_path, "svc-a")
        _write(tmp_path, "svc-b/requirements.txt", "requests\n")
        _write(tmp_path, "svc-c/requirements.txt", "flask\n")

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert sorted(v.path for v in violations) == ["svc-b", "svc-c"]


class TestLockedProjects:
    def test_uv_project_with_current_lock_passes(self, tmp_path: Path):
        _uv_project(tmp_path)

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_exported_requirements_next_to_uv_lock_passes(self, tmp_path: Path):
        _uv_project(tmp_path)
        _write(tmp_path, "requirements.txt", "requests==2.32.0\n")

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_stale_lock_fails(self, tmp_path: Path):
        _uv_project(tmp_path)

        violations = find_violations(tmp_path, check_fresh=_stale)

        assert _codes(violations) == ["stale-uv-lock"]

    def test_unparseable_lock_fails_without_running_freshness_check(
        self, tmp_path: Path
    ):
        _write(tmp_path, "pyproject.toml", PYPROJECT.format(name="demo"))
        _write(tmp_path, "uv.lock", "this is not = = toml")

        violations = find_violations(
            tmp_path, check_fresh=lambda _: pytest.fail("must not run")
        )

        assert _codes(violations) == ["invalid-uv-lock"]

    def test_lock_without_packages_fails(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", PYPROJECT.format(name="demo"))
        _write(tmp_path, "uv.lock", "version = 1\n")

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "invalid-uv-lock"
        ]

    def test_missing_uv_binary_fails_closed(self, tmp_path: Path):
        _uv_project(tmp_path)

        violations = find_violations(
            tmp_path, check_fresh=lambda _: "uv-unavailable"
        )

        assert _codes(violations) == ["uv-unavailable"]

    def test_unparseable_pyproject_fails(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", "[project\nname=")

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "bad-pyproject"
        ]

    def test_poetry_state_next_to_uv_lock_is_a_mixed_locker(self, tmp_path: Path):
        _uv_project(tmp_path)
        _write(tmp_path, "poetry.lock", "")

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "mixed-locker"
        ]


class TestWorkspaces:
    def _workspace(self, root: Path) -> None:
        _write(
            root, "pyproject.toml",
            '[tool.uv.workspace]\nmembers = ["services/*"]\n',
        )
        _write(root, "uv.lock", LOCK.format(name="root"))
        _write(root, "services/api/pyproject.toml", PYPROJECT.format(name="api"))
        _write(root, "services/worker/pyproject.toml", PYPROJECT.format(name="worker"))

    def test_members_are_covered_by_root_lock(self, tmp_path: Path):
        self._workspace(tmp_path)

        assert find_violations(tmp_path, check_fresh=_fresh) == []

    def test_non_member_under_workspace_root_is_not_covered(self, tmp_path: Path):
        self._workspace(tmp_path)
        _write(tmp_path, "tools/pyproject.toml", PYPROJECT.format(name="tools"))

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert [(v.path, v.code) for v in violations] == [
            ("tools", "missing-uv-lock")
        ]

    def test_workspace_lock_is_freshness_checked_once(self, tmp_path: Path):
        self._workspace(tmp_path)
        checked: list[Path] = []

        def record(lock_dir: Path) -> None:
            checked.append(lock_dir)

        find_violations(tmp_path, check_fresh=record)

        assert checked == [tmp_path.resolve()]


class TestMain:
    def _config(self, root: Path, body: str) -> None:
        _write(
            root, ".security/config.yml",
            f"email:\n  to: [a@example.invalid]\n{body}",
        )

    def test_passes_when_not_opted_in_even_if_unlocked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        _write(tmp_path, "requirements.txt", "requests\n")

        rc = python_lock_gate.main(["--workspace", str(tmp_path)])

        assert rc == 0
        assert "gate passes" in capsys.readouterr().out

    def test_fails_when_opted_in_and_unlocked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        self._config(tmp_path, "python:\n  require_uv_lock: true\n")
        _write(tmp_path, "requirements.txt", "requests\n")

        rc = python_lock_gate.main(["--workspace", str(tmp_path)])

        assert rc == 1
        assert "missing-uv-lock" in capsys.readouterr().out

    def test_respects_lock_exclude_from_config(self, tmp_path: Path):
        self._config(
            tmp_path,
            "python:\n  require_uv_lock: true\n  lock_exclude: [legacy]\n",
        )
        _write(tmp_path, "legacy/requirements.txt", "requests\n")

        assert python_lock_gate.main(["--workspace", str(tmp_path)]) == 0

    def test_config_defaults_to_not_required(self, tmp_path: Path):
        assert RepoConfig.load(tmp_path).python.require_uv_lock is False


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
class TestRealUv:
    def _lock(self, root: Path, requires_python: str) -> None:
        _write(
            root, "pyproject.toml",
            f'[project]\nname = "demo"\nversion = "0.1.0"\n'
            f'requires-python = "{requires_python}"\ndependencies = []\n',
        )

    def test_current_lock_passes_and_edited_manifest_goes_stale(self, tmp_path: Path):
        self._lock(tmp_path, ">=3.11")
        subprocess.run(["uv", "lock"], cwd=tmp_path, check=True, capture_output=True)

        assert find_violations(tmp_path) == []

        self._lock(tmp_path, ">=3.12")

        assert _codes(find_violations(tmp_path)) == ["stale-uv-lock"]


class TestEdgeCases:
    def test_workspace_exclude_key_leaves_member_uncovered(self, tmp_path: Path):
        _write(
            tmp_path, "pyproject.toml",
            '[tool.uv.workspace]\nmembers = ["pkgs/*"]\nexclude = ["pkgs/skip"]\n',
        )
        _write(tmp_path, "uv.lock", LOCK.format(name="root"))
        _write(tmp_path, "pkgs/ok/pyproject.toml", PYPROJECT.format(name="ok"))
        _write(tmp_path, "pkgs/skip/pyproject.toml", PYPROJECT.format(name="skip"))

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert [(v.path, v.code) for v in violations] == [
            ("pkgs/skip", "missing-uv-lock")
        ]

    def test_dependency_groups_only_pyproject_is_a_project(self, tmp_path: Path):
        _write(
            tmp_path, "pyproject.toml",
            '[dependency-groups]\ndev = ["pytest"]\n',
        )

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "missing-uv-lock"
        ]

    def test_orphan_uv_lock_is_still_validated(self, tmp_path: Path):
        _write(tmp_path, "tools/uv.lock", "not = = toml")

        assert _codes(find_violations(tmp_path, check_fresh=_fresh)) == [
            "invalid-uv-lock"
        ]

    def test_requirements_dir_under_a_locked_repo_is_flagged(self, tmp_path: Path):
        _uv_project(tmp_path)
        _write(tmp_path, "docs/requirements.txt", "sphinx\n")

        violations = find_violations(tmp_path, check_fresh=_fresh)

        assert [(v.path, v.code) for v in violations] == [("docs", "missing-uv-lock")]

    def test_quoted_false_does_not_opt_in(self, tmp_path: Path):
        _write(
            tmp_path, ".security/config.yml",
            'email:\n  to: [a@example.invalid]\npython:\n  require_uv_lock: "false"\n',
        )

        assert RepoConfig.load(tmp_path).python.require_uv_lock is False
