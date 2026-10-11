"""Static checks that need no scanner binaries."""
from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GITLEAKS_TOML = REPO_ROOT / "config" / "defaults" / "gitleaks.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-scan.yml"


def _scan_step(name_prefix: str) -> dict:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    return next(
        step for step in workflow["jobs"]["scan"]["steps"]
        if step.get("name", "").startswith(name_prefix)
    )


def test_gitleaks_config_uses_the_array_form_current_gitleaks_accepts():
    # `[[allowlist]]` (singular array of tables) fails to load on gitleaks
    # 8.30.x with "'AllowList' expected a map, got 'slice'". The array form is
    # `[[allowlists]]`; a singular `allowlist` must be a single table.
    config = tomllib.loads(GITLEAKS_TOML.read_text())

    assert not isinstance(config.get("allowlist"), list)
    assert isinstance(config["allowlists"], list)


def test_gitleaks_step_redacts_and_does_not_swallow_its_exit_code():
    script = _scan_step("Gitleaks")["run"]

    assert "--redact" in script
    assert "|| rc=$?" in script
    assert "scan_guard.py record gitleaks" in script


def test_semgrep_step_does_not_swallow_errors_or_pass_rules_as_one_arg():
    script = _scan_step("Semgrep")["run"]

    assert "|| true" not in script
    assert '--config "$SEMGREP_RULES"' not in script
    assert "semgrep-args" in script
    assert "scan_guard.py record semgrep" in script


def test_scan_job_enforces_scanner_health_after_uploading_the_artifact():
    steps = [s.get("name", "") for s in
             yaml.safe_load(WORKFLOW.read_text())["jobs"]["scan"]["steps"]]

    assert "Enforce scanner health" in steps
    assert steps.index("Enforce scanner health") > steps.index(
        "Upload results artifact"
    )


def test_notify_and_gate_still_run_when_the_scan_job_is_red():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]

    assert jobs["notify"]["if"] == "${{ !cancelled() }}"
    assert jobs["gate"]["if"] == "${{ !cancelled() }}"


def test_scan_job_checks_out_the_guard_script():
    checkout = next(
        s for s in yaml.safe_load(WORKFLOW.read_text())["jobs"]["scan"]["steps"]
        if s.get("name") == "Checkout security-infra config"
    )

    assert "scripts/secinfra" in checkout["with"]["sparse-checkout"]
