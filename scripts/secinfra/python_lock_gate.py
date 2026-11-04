"""Python lock merge-gate: every Python project must be locked with uv.

Walks the caller repo and fails when any directory that declares Python
dependencies is not governed by a committed, parseable, up-to-date uv.lock.
Opt-in via `python.require_uv_lock: true` in .security/config.yml; until a
repo sets it, this gate passes unconditionally.

A project is governed by a uv.lock when either:
  - its own directory holds one, or
  - an ancestor holding a uv.lock lists it under [tool.uv.workspace] members.

Violations:
  missing-uv-lock  no governing uv.lock (names the tool in use instead:
                   poetry, pipenv, or bare requirements.txt)
  mixed-locker     uv.lock coexists with poetry/pipenv lock state
  invalid-uv-lock  uv.lock does not parse or lists no packages
  stale-uv-lock    `uv lock --check` says the lock no longer matches
                   pyproject.toml
  bad-pyproject    pyproject.toml does not parse
  uv-unavailable   the uv binary is not on PATH, so freshness can't be proven
                   (fails closed)

CI checks out tracked files only, so a uv.lock that exists in the workspace
is already committed.

Usage:
    python -m secinfra.python_lock_gate --workspace .
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .common.config import RepoConfig
from .common.python_projects import (
    UV_LOCK,
    PythonProject,
    covering_lock_dir,
    discover_projects,
    find_uv_lock_dirs,
)

FreshnessCheck = Callable[[Path], "str | None"]


@dataclass(frozen=True)
class Violation:
    path: str
    code: str
    reason: str


def uv_lock_check(lock_dir: Path) -> str | None:
    """Return None when uv.lock matches the project, else an explanation."""
    uv = shutil.which("uv")
    if uv is None:
        return "uv-unavailable"
    proc = subprocess.run(
        [uv, "lock", "--check"],
        cwd=lock_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return None
    detail = (proc.stderr or proc.stdout).strip().splitlines()
    return detail[-1] if detail else f"uv lock --check exited {proc.returncode}"


def _rel(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve())
    return str(rel) if str(rel) != "." else "."


def _missing_lock_reason(project: PythonProject) -> str:
    if project.uses_poetry:
        return "uses poetry; migrate to uv and commit uv.lock"
    if project.uses_pipenv:
        return "uses pipenv; migrate to uv and commit uv.lock"
    if project.has_requirements and "pyproject.toml" not in project.manifests:
        return (
            "requirements.txt is not a lockfile; add a pyproject.toml and "
            "commit uv.lock (generate requirements.txt with `uv export` if needed)"
        )
    return "no uv.lock committed for this project"


def _lockfile_problem(lock_dir: Path) -> str | None:
    """Return why uv.lock is unusable, or None when it parses with packages."""
    try:
        data = tomllib.loads((lock_dir / UV_LOCK).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return f"uv.lock does not parse: {exc}"
    if "version" not in data or not data.get("package"):
        return "uv.lock has no version or lists no packages"
    return None


def _project_violations(
    project: PythonProject,
    root: Path,
    all_projects: list[PythonProject],
) -> tuple[list[Violation], Path | None]:
    rel = _rel(project.path, root)
    if project.pyproject_error:
        return [Violation(rel, "bad-pyproject", project.pyproject_error)], None

    lock_dir = covering_lock_dir(project, root, all_projects)
    if lock_dir is None:
        return [Violation(rel, "missing-uv-lock", _missing_lock_reason(project))], None

    violations: list[Violation] = []
    if project.uses_poetry or project.uses_pipenv:
        violations.append(Violation(
            rel, "mixed-locker",
            "uv.lock coexists with poetry/pipenv state; keep uv as the only locker",
        ))
    return violations, lock_dir


def find_violations(
    root: Path,
    exclude: list[str] | None = None,
    check_fresh: FreshnessCheck = uv_lock_check,
) -> list[Violation]:
    root = root.resolve()
    projects = discover_projects(root, exclude)
    violations: list[Violation] = []
    lock_dirs: set[Path] = set()

    for project in projects:
        found, lock_dir = _project_violations(project, root, projects)
        violations.extend(found)
        if lock_dir is not None:
            lock_dirs.add(lock_dir)

    # A uv.lock no discovered project claims (orphan, or beside a manifest we
    # don't recognise) still gets validated: python_envs syncs it too.
    lock_dirs.update(find_uv_lock_dirs(root, exclude))

    for lock_dir in sorted(lock_dirs):
        rel = _rel(lock_dir, root)
        problem = _lockfile_problem(lock_dir)
        if problem:
            violations.append(Violation(rel, "invalid-uv-lock", problem))
            continue
        stale = check_fresh(lock_dir)
        if stale == "uv-unavailable":
            violations.append(Violation(
                rel, "uv-unavailable",
                "uv is not installed, cannot verify uv.lock is up to date",
            ))
        elif stale:
            violations.append(Violation(
                rel, "stale-uv-lock", f"uv.lock is out of date: {stale}",
            ))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a Python project is not locked with uv"
    )
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)

    workspace = args.workspace or os.environ.get("GITHUB_WORKSPACE", ".")
    config = RepoConfig.load(workspace)
    policy = config.python
    if not policy.require_uv_lock:
        print(
            "python.require_uv_lock: false (default) — uv.lock not required; "
            "gate passes."
        )
        return 0

    violations = find_violations(Path(workspace), policy.lock_exclude)
    if violations:
        print(f"FAIL: {len(violations)} Python locking violation(s).")
        for v in violations:
            print(f"  - {v.path}: [{v.code}] {v.reason}")
        return 1

    print("PASS: every Python project is locked with a current uv.lock.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
