"""Discover Python projects and uv lockfiles in a checked-out repo.

Shared by the uv.lock merge gate (python_lock_gate), the Bumblebee venv
builder (python_envs) and the Bumblebee gate's coverage check. Stdlib only.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

UV_LOCK = "uv.lock"

# Directories that never hold first-party project manifests. Anything holding
# a pyvenv.cfg is pruned as well, whatever it is called.
SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", ".tox", ".nox", "__pycache__",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "site-packages",
    ".secinfra", ".bumblebee-src",
})

_MANIFEST_FILES = frozenset({
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock",
    "Pipfile.lock",
})


@dataclass(frozen=True)
class PythonProject:
    """A directory that declares Python dependencies."""

    path: Path
    manifests: tuple[str, ...]
    pyproject: dict = field(default_factory=dict, compare=False)
    pyproject_error: str = field(default="", compare=False)

    @property
    def uses_poetry(self) -> bool:
        return (
            "poetry.lock" in self.manifests
            or "tool" in self.pyproject
            and "poetry" in self.pyproject["tool"]
        )

    @property
    def uses_pipenv(self) -> bool:
        return "Pipfile" in self.manifests or "Pipfile.lock" in self.manifests

    @property
    def has_requirements(self) -> bool:
        return any(m.endswith(".txt") for m in self.manifests)

    def _uv_workspace(self) -> dict:
        return self.pyproject.get("tool", {}).get("uv", {}).get("workspace", {})

    @property
    def uv_workspace_members(self) -> list[str]:
        return [str(m) for m in self._uv_workspace().get("members", [])]

    @property
    def uv_workspace_exclude(self) -> list[str]:
        return [str(m) for m in self._uv_workspace().get("exclude", [])]


def normalize_excludes(root: Path, exclude: list[str]) -> list[Path]:
    """Turn user-supplied repo-relative paths into absolute, resolved paths."""
    return [(root / e).resolve() for e in exclude if str(e).strip()]


def is_excluded(path: Path, excludes: list[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == ex or ex in resolved.parents for ex in excludes)


def _walk(root: Path, excludes: list[Path]):
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if (here / "pyvenv.cfg").exists():
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not is_excluded(here / d, excludes)
        )
        yield here, filenames


def _is_python_manifest(name: str) -> bool:
    return name in _MANIFEST_FILES or (
        name.startswith("requirements") and name.endswith(".txt")
    )


def _load_pyproject(path: Path) -> tuple[dict, str]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")), ""
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return {}, str(exc)


def _declares_project(pyproject: dict) -> bool:
    """A pyproject.toml holding only tool config (ruff, black...) isn't a project."""
    tool = pyproject.get("tool", {})
    return (
        "project" in pyproject
        or "dependency-groups" in pyproject
        or "poetry" in tool
        or "uv" in tool
    )


def discover_projects(
    root: Path, exclude: list[str] | None = None
) -> list[PythonProject]:
    """Every directory under root that declares Python dependencies."""
    root = root.resolve()
    excludes = normalize_excludes(root, exclude or [])
    projects: list[PythonProject] = []
    for here, filenames in _walk(root, excludes):
        manifests = tuple(sorted(f for f in filenames if _is_python_manifest(f)))
        if not manifests:
            continue
        pyproject: dict = {}
        error = ""
        if "pyproject.toml" in manifests:
            pyproject, error = _load_pyproject(here / "pyproject.toml")
            if not error and not _declares_project(pyproject):
                manifests = tuple(m for m in manifests if m != "pyproject.toml")
                if not manifests:
                    continue
        projects.append(PythonProject(here, manifests, pyproject, error))
    return projects


def find_uv_lock_dirs(root: Path, exclude: list[str] | None = None) -> list[Path]:
    """Directories under root that contain a uv.lock."""
    root = root.resolve()
    excludes = normalize_excludes(root, exclude or [])
    return [h for h, files in _walk(root, excludes) if UV_LOCK in files]


def covering_lock_dir(
    project: PythonProject,
    root: Path,
    projects: list[PythonProject],
) -> Path | None:
    """The directory whose uv.lock governs this project, or None.

    That is the project's own directory when it holds a uv.lock, otherwise the
    nearest ancestor (inside root) holding a uv.lock whose pyproject.toml
    declares a [tool.uv.workspace] that lists this project as a member.
    """
    root = root.resolve()
    if (project.path / UV_LOCK).is_file():
        return project.path
    by_path = {p.path: p for p in projects}
    for ancestor in project.path.parents:
        if root not in (ancestor, *ancestor.parents):
            break
        owner = by_path.get(ancestor)
        if owner is None or not (ancestor / UV_LOCK).is_file():
            continue
        if project.path in _workspace_member_dirs(owner):
            return ancestor
    return None


def _workspace_member_dirs(owner: PythonProject) -> set[Path]:
    """Dirs matched by [tool.uv.workspace] members minus its exclude globs."""
    def expand(patterns: list[str]) -> set[Path]:
        return {
            p.resolve()
            for pattern in patterns
            for p in owner.path.glob(pattern)
            if p.is_dir()
        }

    return expand(owner.uv_workspace_members) - expand(owner.uv_workspace_exclude)


def registry_package_count(lock_dir: Path) -> int:
    """Third-party (registry-sourced) packages recorded in lock_dir/uv.lock.

    Workspace members and the root project carry `virtual`/`editable` sources
    and are first-party, so a project with no real dependencies counts zero.
    An unreadable lock counts zero; the lock gate reports it separately.
    """
    try:
        data = tomllib.loads((lock_dir / UV_LOCK).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return 0
    return sum(
        1 for pkg in data.get("package", [])
        if isinstance(pkg.get("source"), dict) and "registry" in pkg["source"]
    )
