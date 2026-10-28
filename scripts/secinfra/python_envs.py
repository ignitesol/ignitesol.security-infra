"""Materialize Python environments for the Bumblebee scan.

Bumblebee's PyPI source is installed metadata (*.dist-info/METADATA); it does
not read uv.lock or requirements.txt. So the scan job builds one venv per
locked project and passes each as its own `--root`. One venv per project (not
one shared env) keeps per-Lambda / per-service pins from clobbering each other.

  uv.lock projects  `uv sync --frozen` into a venv holding exactly the locked
                    versions. A failed sync is FATAL: a lock we could not
                    install is a project Bumblebee silently never scanned.
  legacy projects   requirements*.txt in a directory no uv.lock governs get
                    the old best-effort pip venv. Failures only warn, as they
                    always did, until those repos migrate to uv.

Venvs live outside the checkout so the `--root .` walk doesn't re-scan them.
`python.lock_exclude` from .security/config.yml is honoured (needs pyyaml, so
the workflow installs secinfra first); with no config it excludes nothing.

Usage:
    python -m secinfra.python_envs --workspace . \\
        --venv-base "$RUNNER_TEMP/secinfra-venvs" \\
        --roots-file "$RUNNER_TEMP/secinfra-venv-roots"

    # Just list the uv.lock directories (exclusions applied), one per line:
    python -m secinfra.python_envs --workspace . --list-lock-dirs FILE
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .common.config import RepoConfig
from .common.python_projects import (
    covering_lock_dir,
    discover_projects,
    find_uv_lock_dirs,
    is_excluded,
    normalize_excludes,
)

_UV_SYNC_FLAGS = [
    "sync", "--frozen", "--all-packages", "--all-groups", "--all-extras",
    "--no-install-workspace",
]


def _slug(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve())
    return "root" if str(rel) == "." else str(rel).replace("/", "_").replace(".", "_")


def _sync_uv_project(uv: str, lock_dir: Path, venv: Path) -> bool:
    env = {**os.environ, "UV_PROJECT_ENVIRONMENT": str(venv)}
    proc = subprocess.run(
        [uv, *_UV_SYNC_FLAGS], cwd=lock_dir, env=env, check=False,
    )
    return proc.returncode == 0


def _pip_venv(requirements: Path, venv: Path) -> bool:
    steps = (
        [sys.executable, "-m", "venv", str(venv)],
        [str(venv / "bin" / "pip"), "install", "--quiet", "-r", str(requirements)],
    )
    return all(
        subprocess.run(cmd, check=False).returncode == 0 for cmd in steps
    )


def build(
    workspace: Path,
    venv_base: Path,
    exclude: list[str] | None = None,
) -> tuple[list[Path], list[str]]:
    """Build venvs; return (venv roots, fatal error messages)."""
    workspace = workspace.resolve()
    venv_base.mkdir(parents=True, exist_ok=True)
    roots: list[Path] = []
    errors: list[str] = []

    lock_dirs = find_uv_lock_dirs(workspace, exclude)
    uv = shutil.which("uv")
    for lock_dir in lock_dirs:
        rel = lock_dir.relative_to(workspace)
        print(f"--- uv sync --frozen in {rel} ---", flush=True)
        if uv is None:
            errors.append(f"{rel}: uv is not installed, cannot build venv")
            continue
        venv = venv_base / _slug(lock_dir, workspace)
        if _sync_uv_project(uv, lock_dir, venv):
            roots.append(venv)
        else:
            errors.append(f"{rel}: `uv sync --frozen` failed")

    excludes = normalize_excludes(workspace, exclude or [])
    projects = discover_projects(workspace, exclude)
    for project in projects:
        # Only a project its own uv.lock (or a workspace root's) governs is
        # covered above; a requirements.txt in an ungoverned subdirectory of
        # a uv repo still needs the pip venv.
        if covering_lock_dir(project, workspace, projects) is not None:
            continue
        for req in sorted(project.path.glob("requirements*.txt")):
            if is_excluded(req, excludes):
                continue
            venv = venv_base / _slug(req, workspace)
            rel = req.relative_to(workspace)
            print(f"--- legacy pip venv for {rel} ---", flush=True)
            if _pip_venv(req, venv):
                roots.append(venv)
            else:
                print(
                    f"::warning::could not install {rel}; "
                    "Bumblebee will not see its PyPI packages",
                    flush=True,
                )
    return roots, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build venvs for the Bumblebee scan")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--venv-base")
    parser.add_argument("--roots-file")
    parser.add_argument("--list-lock-dirs", metavar="FILE")
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)

    workspace = Path(args.workspace)
    exclude = [*RepoConfig.load(workspace).python.lock_exclude, *args.exclude]

    if args.list_lock_dirs:
        dirs = find_uv_lock_dirs(workspace, exclude)
        Path(args.list_lock_dirs).write_text("".join(f"{d}\n" for d in dirs))
        return 0
    if not (args.venv_base and args.roots_file):
        parser.error("--venv-base and --roots-file are required to build venvs")

    roots, errors = build(workspace, Path(args.venv_base), exclude)
    Path(args.roots_file).write_text("".join(f"{r}\n" for r in roots))
    print(f"Built {len(roots)} venv(s)")
    for message in errors:
        print(f"::error::{message}", flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
