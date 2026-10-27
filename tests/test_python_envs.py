"""Venv building for Bumblebee, and the gate's refusal to pass an empty PyPI scan."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from secinfra import bumblebee_gate, python_envs

PYPROJECT = (
    '[project]\nname = "{name}"\nversion = "0.1.0"\n'
    'requires-python = ">=3.11"\n'
)
LOCK_NO_DEPS = (
    'version = 1\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n'
    'source = { virtual = "." }\n'
)
LOCK_WITH_DEP = (
    LOCK_NO_DEPS
    + '\n[[package]]\nname = "requests"\nversion = "2.32.0"\n'
    + 'source = { registry = "https://pypi.org/simple" }\n'
)


def _write(root: Path, rel: str, content: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class TestBuild:
    def test_one_venv_per_uv_lock_dir_passed_as_a_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "svc-a/pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "svc-a/uv.lock", LOCK_WITH_DEP)
        _write(ws, "svc-b/pyproject.toml", PYPROJECT.format(name="b"))
        _write(ws, "svc-b/uv.lock", LOCK_WITH_DEP)
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        synced: list[tuple[str, str]] = []

        def fake_sync(uv: str, lock_dir: Path, venv: Path) -> bool:
            synced.append((lock_dir.name, venv.name))
            return True

        monkeypatch.setattr(python_envs, "_sync_uv_project", fake_sync)

        roots, errors = python_envs.build(ws, tmp_path / "venvs")

        assert errors == []
        assert synced == [("svc-a", "svc-a"), ("svc-b", "svc-b")]
        assert [r.name for r in roots] == ["svc-a", "svc-b"]

    def test_failed_uv_sync_is_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "uv.lock", LOCK_WITH_DEP)
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        monkeypatch.setattr(python_envs, "_sync_uv_project", lambda *a: False)

        roots, errors = python_envs.build(ws, tmp_path / "venvs")

        assert roots == []
        assert len(errors) == 1 and "uv sync --frozen" in errors[0]

    def test_missing_uv_binary_is_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "uv.lock", LOCK_WITH_DEP)
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: None)

        _, errors = python_envs.build(ws, tmp_path / "venvs")

        assert "uv is not installed" in errors[0]

    def test_legacy_requirements_get_pip_venv_and_failures_only_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        ws = tmp_path / "ws"
        _write(ws, "ok/requirements.txt", "requests\n")
        _write(ws, "bad/requirements.txt", "nope\n")
        monkeypatch.setattr(
            python_envs, "_pip_venv", lambda req, venv: req.parent.name == "ok"
        )

        roots, errors = python_envs.build(ws, tmp_path / "venvs")

        assert errors == []
        assert [r.name for r in roots] == ["ok_requirements_txt"]
        assert "::warning::" in capsys.readouterr().out

    def test_requirements_inside_a_uv_project_are_not_pip_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "uv.lock", LOCK_WITH_DEP)
        _write(ws, "requirements.txt", "requests==2.32.0\n")
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        monkeypatch.setattr(python_envs, "_sync_uv_project", lambda *a: True)
        monkeypatch.setattr(
            python_envs, "_pip_venv", lambda *a: pytest.fail("must not run")
        )

        roots, _ = python_envs.build(ws, tmp_path / "venvs")

        assert len(roots) == 1

    def test_requirements_in_an_ungoverned_subdir_of_a_uv_repo_still_get_a_venv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "uv.lock", LOCK_WITH_DEP)
        _write(ws, "lambdas/f/requirements.txt", "requests\n")
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        monkeypatch.setattr(python_envs, "_sync_uv_project", lambda *a: True)
        piped: list[str] = []
        monkeypatch.setattr(
            python_envs, "_pip_venv",
            lambda req, venv: piped.append(req.parent.name) or True,
        )

        roots, _ = python_envs.build(ws, tmp_path / "venvs")

        assert piped == ["f"]
        assert len(roots) == 2

    def test_main_honours_lock_exclude_from_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, ".security/config.yml",
               "email:\n  to: [a@example.invalid]\n"
               "python:\n  lock_exclude: [fixtures]\n")
        _write(ws, "fixtures/pyproject.toml", PYPROJECT.format(name="f"))
        _write(ws, "fixtures/uv.lock", LOCK_WITH_DEP)
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        monkeypatch.setattr(
            python_envs, "_sync_uv_project", lambda *a: pytest.fail("excluded")
        )

        rc = python_envs.main([
            "--workspace", str(ws),
            "--venv-base", str(tmp_path / "venvs"),
            "--roots-file", str(tmp_path / "roots"),
        ])

        assert rc == 0

    def test_list_lock_dirs_writes_unexcluded_dirs(self, tmp_path: Path):
        ws = tmp_path / "ws"
        _write(ws, "a/uv.lock", LOCK_WITH_DEP)
        _write(ws, "node_modules/x/uv.lock", LOCK_WITH_DEP)
        out = tmp_path / "dirs"

        rc = python_envs.main(["--workspace", str(ws), "--list-lock-dirs", str(out)])

        assert rc == 0
        assert out.read_text().splitlines() == [str((ws / "a").resolve())]

    def test_main_writes_roots_file_and_exits_nonzero_on_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = tmp_path / "ws"
        _write(ws, "pyproject.toml", PYPROJECT.format(name="a"))
        _write(ws, "uv.lock", LOCK_WITH_DEP)
        monkeypatch.setattr(python_envs.shutil, "which", lambda _: "/usr/bin/uv")
        monkeypatch.setattr(python_envs, "_sync_uv_project", lambda *a: False)
        roots_file = tmp_path / "roots"

        rc = python_envs.main([
            "--workspace", str(ws),
            "--venv-base", str(tmp_path / "venvs"),
            "--roots-file", str(roots_file),
        ])

        assert rc == 1
        assert roots_file.read_text() == ""


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_real_uv_sync_builds_a_venv_for_a_dependency_free_lock(tmp_path: Path):
    import subprocess

    ws = tmp_path / "ws"
    _write(
        ws, "pyproject.toml",
        '[project]\nname = "demo"\nversion = "0.1.0"\n'
        'requires-python = ">=3.11"\ndependencies = []\n',
    )
    subprocess.run(["uv", "lock"], cwd=ws, check=True, capture_output=True)

    roots, errors = python_envs.build(ws, tmp_path / "venvs")

    assert errors == []
    assert [(r / "pyvenv.cfg").is_file() for r in roots] == [True]


class TestBumblebeeGateCoverage:
    def _setup(
        self, tmp_path: Path, lock: str, records: list[dict]
    ) -> tuple[Path, Path]:
        ws = tmp_path / "ws"
        _write(ws, ".security/config.yml",
               "email:\n  to: [a@example.invalid]\nsystems:\n"
               "  bumblebee:\n    fail_on: any\n")
        _write(ws, "pyproject.toml", PYPROJECT.format(name="demo"))
        _write(ws, "uv.lock", lock)
        results = tmp_path / "results"
        _write(results, "bumblebee.ndjson",
               "\n".join(json.dumps(r) for r in records) + "\n")
        return ws, results

    def _run(self, ws: Path, results: Path) -> int:
        return bumblebee_gate.main(
            ["--results-dir", str(results), "--workspace", str(ws)]
        )

    def test_fails_when_locked_deps_but_no_pypi_records(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        ws, results = self._setup(tmp_path, LOCK_WITH_DEP, [])

        assert self._run(ws, results) == 1
        assert "no PyPI" in capsys.readouterr().out

    def test_fails_when_only_npm_records_present(self, tmp_path: Path):
        records = [{"record_type": "package", "ecosystem": "npm", "package_name": "x"}]
        ws, results = self._setup(tmp_path, LOCK_WITH_DEP, records)

        assert self._run(ws, results) == 1

    def test_passes_when_pypi_records_present(self, tmp_path: Path):
        records = [{"record_type": "package", "ecosystem": "pypi",
                    "package_name": "requests", "version": "2.32.0"}]
        ws, results = self._setup(tmp_path, LOCK_WITH_DEP, records)

        assert self._run(ws, results) == 0

    def test_dependency_free_project_passes_with_no_pypi_records(self, tmp_path: Path):
        ws, results = self._setup(tmp_path, LOCK_NO_DEPS, [])

        assert self._run(ws, results) == 0

    def test_not_enforced_when_gating_not_opted_in(self, tmp_path: Path):
        ws, results = self._setup(tmp_path, LOCK_WITH_DEP, [])
        _write(ws, ".security/config.yml", "email:\n  to: [a@example.invalid]\n")

        assert self._run(ws, results) == 0


class TestScanFailureFailsClosed:
    """A failed scan job must not let an opted-in gate pass."""

    def _ws(self, tmp_path: Path, body: str) -> Path:
        ws = tmp_path / "ws"
        _write(ws, ".security/config.yml", f"email:\n  to: [a@example.invalid]\n{body}")
        return ws

    def test_bumblebee_gate_fails_when_scan_failed_and_gating_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = self._ws(tmp_path, "systems:\n  bumblebee:\n    fail_on: any\n")
        monkeypatch.setenv("SECINFRA_SCAN_RESULT", "failure")

        rc = bumblebee_gate.main(
            ["--results-dir", str(tmp_path / "none"), "--workspace", str(ws)]
        )

        assert rc == 1

    def test_bumblebee_gate_ignores_failed_scan_when_not_opted_in(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = self._ws(tmp_path, "")
        monkeypatch.setenv("SECINFRA_SCAN_RESULT", "failure")

        rc = bumblebee_gate.main(
            ["--results-dir", str(tmp_path / "none"), "--workspace", str(ws)]
        )

        assert rc == 0

    def test_license_gate_fails_when_scan_failed_and_policy_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from secinfra import license_gate

        ws = self._ws(tmp_path, "license:\n  policy:\n    deny_unknown: true\n")
        monkeypatch.setenv("SECINFRA_SCAN_RESULT", "failure")

        rc = license_gate.main(
            ["--results-dir", str(tmp_path / "none"), "--workspace", str(ws)]
        )

        assert rc == 1

    def test_license_gate_passes_without_policy_even_if_scan_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from secinfra import license_gate

        ws = self._ws(tmp_path, "")
        monkeypatch.setenv("SECINFRA_SCAN_RESULT", "failure")

        rc = license_gate.main(
            ["--results-dir", str(tmp_path / "none"), "--workspace", str(ws)]
        )

        assert rc == 0

    def test_unset_scan_result_is_treated_as_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        ws = self._ws(tmp_path, "systems:\n  bumblebee:\n    fail_on: any\n")
        monkeypatch.delenv("SECINFRA_SCAN_RESULT", raising=False)

        rc = bumblebee_gate.main(
            ["--results-dir", str(tmp_path / "none"), "--workspace", str(ws)]
        )

        assert rc == 0
