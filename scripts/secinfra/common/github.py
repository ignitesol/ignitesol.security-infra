"""GitHub Actions context helpers and manifest state-branch utilities."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

# Where per-repo dependency manifests are persisted. A dedicated, unprotected
# orphan branch keeps the full git-history audit trail in-repo without pushing
# to (PR-protected) default branches. Override via SECINFRA_STATE_BRANCH.
DEFAULT_STATE_BRANCH = "secinfra/manifests"

_BOT_IDENT = {
    "GIT_AUTHOR_NAME": "secinfra-bot",
    "GIT_AUTHOR_EMAIL": "secinfra-bot@ignitesol.com",
    "GIT_COMMITTER_NAME": "secinfra-bot",
    "GIT_COMMITTER_EMAIL": "secinfra-bot@ignitesol.com",
}


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


def state_branch() -> str:
    """Branch where per-repo dependency manifests are persisted."""
    return os.environ.get("SECINFRA_STATE_BRANCH", DEFAULT_STATE_BRANCH)


def _git(*args: str, cwd: str, check: bool = True, env: dict | None = None):
    return subprocess.run(
        ["git", *args],
        cwd=cwd, check=check, env=env or {**os.environ}, capture_output=True,
    )


def read_state_manifest(
    manifest_file: str,
    *,
    workspace: str | None = None,
    branch: str | None = None,
) -> dict:
    """Read a manifest JSON from the dedicated state branch.

    Returns {} if the branch or file does not yet exist (first run).
    Reads via git plumbing only — never checks out or touches the working tree.
    """
    ws = str(Path(workspace or os.environ.get("GITHUB_WORKSPACE", ".")))
    br = branch or state_branch()
    ref = f"refs/remotes/origin/{br}"

    # Best-effort fetch; absent branch is fine (first run).
    fetch = _git(
        "fetch", "origin", f"{br}:{ref}",
        cwd=ws, check=False,
    )
    if fetch.returncode != 0:
        print(f"State branch '{br}' not found yet (first run).", flush=True)
        return {}

    show = _git("show", f"{ref}:{manifest_file}", cwd=ws, check=False)
    if show.returncode != 0:
        print(f"Manifest '{manifest_file}' not on '{br}' yet (first run).", flush=True)
        return {}
    try:
        return json.loads(show.stdout.decode())
    except json.JSONDecodeError:
        print(f"Warning: manifest '{manifest_file}' on '{br}' is not valid JSON.", flush=True)
        return {}


def write_state_manifest(
    manifest_file: str,
    data: dict,
    *,
    workspace: str | None = None,
    branch: str | None = None,
    message: str | None = None,
) -> None:
    """Commit `data` as `manifest_file` onto the dedicated state branch.

    Uses pure git plumbing against a temporary index so the working tree and
    default branch are never touched. Pushes the new commit directly to the
    (unprotected) state branch. Needs only `contents: write` + a fetch-capable
    remote (the default GITHUB_TOKEN suffices for same-repo pushes).
    """
    ws = str(Path(workspace or os.environ.get("GITHUB_WORKSPACE", ".")))
    br = branch or state_branch()
    ref = f"refs/remotes/origin/{br}"

    content = json.dumps(data, indent=2, sort_keys=True) + "\n"

    # Resolve current tip of the state branch (if any) for the parent commit.
    parent = None
    if _git("fetch", "origin", f"{br}:{ref}", cwd=ws, check=False).returncode == 0:
        rev = _git("rev-parse", "--verify", "--quiet", ref, cwd=ws, check=False)
        if rev.returncode == 0:
            parent = rev.stdout.decode().strip() or None

    with tempfile.TemporaryDirectory() as tmp:
        index_file = str(Path(tmp) / "index")
        env = {**os.environ, "GIT_INDEX_FILE": index_file, **_BOT_IDENT}

        # Seed the temp index from the parent tree (preserves other repos' manifests).
        if parent:
            _git("read-tree", parent, cwd=ws, env=env)

        # Hash the manifest content into a blob (stdin → object store).
        blob = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=ws, env=env, input=content.encode(), capture_output=True, check=True,
        ).stdout.decode().strip()

        _git(
            "update-index", "--add", "--cacheinfo", f"100644,{blob},{manifest_file}",
            cwd=ws, env=env,
        )

        tree = _git("write-tree", cwd=ws, env=env).stdout.decode().strip()

        # No-op if the tree is unchanged from the parent commit.
        if parent:
            parent_tree = _git(
                "rev-parse", f"{parent}^{{tree}}", cwd=ws, env=env,
            ).stdout.decode().strip()
            if tree == parent_tree:
                print("Manifest unchanged, nothing to commit.", flush=True)
                return

        commit_args = ["commit-tree", tree, "-m",
                       message or "chore(secinfra): update dependency manifest"]
        if parent:
            commit_args += ["-p", parent]
        commit = _git(*commit_args, cwd=ws, env=env).stdout.decode().strip()

        try:
            _git(
                "push", "origin", f"{commit}:refs/heads/{br}",
                cwd=ws, env=env,
            )
            print(f"Manifest persisted to '{br}': {manifest_file}", flush=True)
        except subprocess.CalledProcessError as exc:
            print(f"Warning: could not push manifest to '{br}': "
                  f"{exc.stderr.decode()}", flush=True)
