"""GitHub Actions context helpers and manifest commit utilities."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return ""


def repo_name() -> str:
    return os.environ.get("GITHUB_REPOSITORY", "unknown/repo").split("/")[-1]


def sha_short() -> str:
    sha = os.environ.get("GITHUB_SHA", "")
    return sha[:7] if sha else "unknown"


def commit_manifest(
    manifest_path: Path,
    data: dict,
    *,
    workspace: str | None = None,
) -> None:
    """Write data to manifest_path and commit it back to the repo.

    Expects the workflow job to have `contents: write` permission and
    for git to be configured (done in the workflow step before calling this).
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True))

    ws = Path(workspace or os.environ.get("GITHUB_WORKSPACE", "."))
    rel = manifest_path.relative_to(ws) if manifest_path.is_absolute() else manifest_path

    env = {**os.environ}
    try:
        subprocess.run(
            ["git", "add", str(rel)],
            cwd=str(ws), check=True, env=env, capture_output=True,
        )
        result = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=str(ws), env=env, capture_output=True,
        )
        if result.returncode == 0:
            print("Manifest unchanged, no commit needed.", flush=True)
            return
        subprocess.run(
            ["git", "commit", "-m",
             f"chore(secinfra): update dependency manifest [skip ci]"],
            cwd=str(ws), check=True, env=env, capture_output=True,
        )
        subprocess.run(
            ["git", "push"],
            cwd=str(ws), check=True, env=env, capture_output=True,
        )
        print(f"Manifest committed and pushed: {rel}", flush=True)
    except subprocess.CalledProcessError as exc:
        print(f"Warning: could not commit manifest: {exc.stderr.decode()}", flush=True)
