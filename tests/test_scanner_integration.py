"""End-to-end checks of the Gitleaks and Semgrep steps in security-scan.yml.

These execute the workflow's real `run:` scripts (extracted from the YAML)
against a throwaway git repo containing a fake secret and an obvious Semgrep
hit, using the real binaries. They are skipped when a binary is missing, and
the Semgrep ones when the rule registry is unreachable.

The fixture is generated at test time, never committed: a committed fake token
would trip secret scanning (and push protection) on this repo itself.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
import yaml
from secinfra.scan_guard import GUARDED_SCANNERS, load_health, unhealthy_scanners

pytestmark = pytest.mark.scanner

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-scan.yml"

# Concatenated so this file doesn't look like a leaked token to scanners.
FAKE_TOKEN = "ghp_" + "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz"

VULNERABLE_APP = f'''import subprocess

GITHUB_TOKEN = "{FAKE_TOKEN}"


def run(cmd):
    return eval(cmd)


def sh(user):
    subprocess.call("ls " + user, shell=True)
'''

needs_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


def _registry_reachable() -> bool:
    try:
        with socket.create_connection(("semgrep.dev", 443), timeout=5):
            return True
    except OSError:
        return False


needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None or not _registry_reachable(),
    reason="semgrep not installed or the rule registry is unreachable",
)


def test_scanners_are_available_when_ci_requires_them():
    """Skips must not hide a CI environment that lost its scanners."""
    if os.environ.get("REQUIRE_SCANNERS") != "1":
        pytest.skip("REQUIRE_SCANNERS not set")

    assert shutil.which("gitleaks"), "gitleaks missing"
    assert shutil.which("semgrep"), "semgrep missing"
    assert _registry_reachable(), "semgrep.dev unreachable"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )


def _step_script(name_prefix: str) -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    for step in workflow["jobs"]["scan"]["steps"]:
        if step.get("name", "").startswith(name_prefix):
            return step["run"]
    raise AssertionError(f"no scan step named {name_prefix!r}")


CLEAN_APP = "def add(a, b):\n    return a + b\n"


@pytest.fixture(params=["vulnerable"])
def workspace(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    """A caller-repo checkout: git repo + `.secinfra` + `results/`."""
    app = CLEAN_APP if request.param == "clean" else VULNERABLE_APP
    ws = tmp_path / "caller"
    ws.mkdir()
    (ws / "app.py").write_text(app)
    _git(ws, "init", "-q")
    _git(ws, "add", "-A")
    _git(
        ws, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
        "commit", "-q", "-m", "init",
    )
    (ws / ".secinfra").symlink_to(REPO_ROOT)
    (ws / "results").mkdir()
    return ws


def _run_step(
    name_prefix: str, ws: Path, **env: str
) -> subprocess.CompletedProcess[str]:
    # Same shell invocation GitHub uses for a bare `run:` on Linux.
    return subprocess.run(
        ["bash", "-e", "-c", _step_script(name_prefix)],
        cwd=ws, capture_output=True, text=True,
        env={
            **os.environ,
            "SCAN_ROOT": ".",
            "SEMGREP_RULES": "p/default p/owasp-top-ten p/secrets",
            "SEMGREP_SEND_METRICS": "off",
            "GITHUB_STEP_SUMMARY": str(ws / "summary.md"),
            **env,
        },
    )


@needs_gitleaks
class TestGitleaksStep:
    def test_default_config_loads_and_detects_the_planted_secret(
        self, workspace: Path
    ):
        proc = _run_step("Gitleaks", workspace)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        report = json.loads((workspace / "results" / "gitleaks.json").read_text())
        assert [leak["RuleID"] for leak in report] == ["github-pat"]
        assert load_health(workspace / "results")["gitleaks"].ok

    def test_secret_value_is_redacted_everywhere(self, workspace: Path):
        proc = _run_step("Gitleaks", workspace)

        assert FAKE_TOKEN not in proc.stdout + proc.stderr
        for artifact in (workspace / "results").iterdir():
            assert FAKE_TOKEN not in artifact.read_text()

    def test_config_that_fails_to_load_fails_the_step_loudly(
        self, workspace: Path, tmp_path: Path
    ):
        # The original defect: `[[allowlist]]` (array of tables) is rejected
        # by gitleaks 8.30.x with "'AllowList' expected a map, got 'slice'".
        legacy = tmp_path / "legacy-secinfra"
        (legacy / "config" / "defaults").mkdir(parents=True)
        (legacy / "config" / "defaults" / "gitleaks.toml").write_text(
            '[extend]\nuseDefault = true\n\n'
            '[[allowlist]]\ndescription = "x"\nregexes = ["placeholder"]\n'
        )
        (legacy / "scripts").symlink_to(REPO_ROOT / "scripts")
        (workspace / ".secinfra").unlink()
        (workspace / ".secinfra").symlink_to(legacy)

        proc = _run_step("Gitleaks", workspace)

        assert proc.returncode != 0
        assert "::error" in proc.stdout
        assert not load_health(workspace / "results")["gitleaks"].ok


@needs_semgrep
class TestSemgrepStep:
    def test_default_rulesets_load_and_flag_the_obvious_vulnerabilities(
        self, workspace: Path
    ):
        proc = _run_step("Semgrep", workspace)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        sarif = json.loads((workspace / "results" / "semgrep.sarif").read_text())
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) > 0
        flagged = {result["ruleId"].rsplit(".", 1)[-1] for result in run["results"]}
        assert {"eval-detected", "subprocess-shell-true"} <= flagged
        assert load_health(workspace / "results")["semgrep"].ok

    def test_single_ruleset_override_still_works(self, workspace: Path):
        proc = _run_step("Semgrep", workspace, SEMGREP_RULES="p/default")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert load_health(workspace / "results")["semgrep"].ok

    def test_unresolvable_ruleset_fails_the_step_loudly(self, workspace: Path):
        proc = _run_step(
            "Semgrep", workspace, SEMGREP_RULES="p/this-ruleset-does-not-exist-xyz"
        )

        assert proc.returncode != 0
        assert "::error" in proc.stdout
        assert not load_health(workspace / "results")["semgrep"].ok

    def test_original_single_argument_bug_is_caught_by_the_guard(
        self, workspace: Path
    ):
        # What the old workflow did: pass the whole space-joined list as ONE
        # --config argument. Semgrep loads zero rules; the guard must notice.
        subprocess.run(
            [
                "semgrep", "--config", "p/default p/owasp-top-ten p/secrets",
                "--sarif", "--output", "results/semgrep.sarif",
                "--no-autofix", ".",
            ],
            cwd=workspace, capture_output=True, text=True,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
        recorded = subprocess.run(
            [
                "python3", ".secinfra/scripts/secinfra/scan_guard.py",
                "record", "semgrep", "--exit-code", "0",
                "--results-dir", "results",
            ],
            cwd=workspace, capture_output=True, text=True,
        )

        assert recorded.returncode != 0
        assert "::error" in recorded.stdout


@needs_gitleaks
@needs_semgrep
@pytest.mark.parametrize("workspace", ["clean"], indirect=True)
def test_clean_repo_is_healthy_with_no_findings(workspace: Path):
    # A clean scan must not be mistaken for a scanner that loaded no rules.
    assert _run_step("Gitleaks", workspace).returncode == 0
    assert _run_step("Semgrep", workspace).returncode == 0

    sarif = json.loads((workspace / "results" / "semgrep.sarif").read_text())
    assert sarif["runs"][0]["results"] == []
    assert json.loads((workspace / "results" / "gitleaks.json").read_text()) == []
    assert unhealthy_scanners(workspace / "results") == []


@needs_gitleaks
@needs_semgrep
def test_enforce_passes_after_both_healthy_scans_and_fails_if_one_is_missing(
    workspace: Path,
):
    enforce = [
        "python3", ".secinfra/scripts/secinfra/scan_guard.py",
        "enforce", "--results-dir", "results",
    ]
    assert _run_step("Gitleaks", workspace).returncode == 0
    partial = subprocess.run(enforce, cwd=workspace, capture_output=True, text=True)
    assert partial.returncode == 1  # semgrep has not reported yet

    assert _run_step("Semgrep", workspace).returncode == 0
    complete = subprocess.run(enforce, cwd=workspace, capture_output=True, text=True)
    assert complete.returncode == 0
    assert set(load_health(workspace / "results")) == set(GUARDED_SCANNERS)
