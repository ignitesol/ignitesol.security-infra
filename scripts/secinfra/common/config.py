"""Load and validate the per-repo .security/config.yml."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class EmailConfig:
    to: list[str]
    cc: list[str] = field(default_factory=list)

    def all_recipients(self, security_cc: str) -> list[str]:
        """Return To list; security_cc is always included in Cc."""
        return self.to


@dataclass
class LicensePolicy:
    deny: list[str] = field(default_factory=list)
    deny_unknown: bool = False
    # User-declared corrections for dependencies whose license can't be
    # machine-detected from package metadata (e.g. a package that ships a
    # LICENSE file but never sets the SPDX classifier/field pip-licenses reads).
    # Keyed "ecosystem/name" (case-insensitive), e.g. {"python/brevo-python": "MIT"}.
    overrides: dict[str, str] = field(default_factory=dict)


@dataclass
class LicenseConfig:
    ecosystems: list[str] = field(default_factory=lambda: ["npm", "python", "java"])
    install: dict[str, str] = field(default_factory=dict)
    policy: LicensePolicy = field(default_factory=LicensePolicy)


def _as_bool(value: object) -> bool:
    """YAML booleans, plus the quoted strings people write ("false", "true")."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "1"}
    return bool(value)


@dataclass
class PythonConfig:
    """Python dependency-locking policy (uv only).

    require_uv_lock: fail the lock gate unless every Python project in the
        repo is governed by a committed, up-to-date uv.lock. Opt-in.
    lock_exclude: repo-relative paths (fixtures, vendored code) the lock
        gate ignores.
    """

    require_uv_lock: bool = False
    lock_exclude: list[str] = field(default_factory=list)


@dataclass
class SystemGate:
    """Per-system enable flag + optional merge-gate threshold.

    Accepts either a plain bool (`security: true`) or a dict
    (`security: {enabled: true, fail_on: high}`) from YAML.
    """

    enabled: bool = True
    fail_on: str = "none"

    @classmethod
    def from_value(cls, value: object) -> "SystemGate":
        if isinstance(value, dict):
            return cls(
                enabled=bool(value.get("enabled", True)),
                fail_on=str(value.get("fail_on") or "none").lower(),
            )
        return cls(enabled=bool(value) if value is not None else True)

    def __bool__(self) -> bool:
        return self.enabled


@dataclass
class SystemsConfig:
    security: SystemGate = field(default_factory=SystemGate)
    bumblebee: SystemGate = field(default_factory=SystemGate)
    license: SystemGate = field(default_factory=SystemGate)


@dataclass
class RepoConfig:
    email: EmailConfig
    systems: SystemsConfig = field(default_factory=SystemsConfig)
    license: LicenseConfig = field(default_factory=LicenseConfig)
    python: PythonConfig = field(default_factory=PythonConfig)
    paths: dict[str, str] = field(default_factory=lambda: {"scan_root": "."})

    @classmethod
    def load(cls, workspace: str | Path | None = None) -> "RepoConfig":
        """Load from <workspace>/.security/config.yml or environment defaults."""
        ws = Path(workspace or os.environ.get("GITHUB_WORKSPACE", "."))
        config_path = ws / ".security" / "config.yml"

        if not config_path.exists():
            return cls._defaults()

        with config_path.open() as fh:
            data = yaml.safe_load(fh) or {}

        email_data = data.get("email", {})
        to_list = email_data.get("to", [])
        if isinstance(to_list, str):
            to_list = [to_list]

        systems_data = data.get("systems", {})
        license_data = data.get("license", {})
        paths_data = data.get("paths", {"scan_root": "."})

        policy_data = license_data.get("policy", {})
        python_data = data.get("python") or {}
        lock_exclude = python_data.get("lock_exclude") or []
        if isinstance(lock_exclude, str):
            lock_exclude = [lock_exclude]

        return cls(
            email=EmailConfig(to=to_list),
            systems=SystemsConfig(
                security=SystemGate.from_value(systems_data.get("security", True)),
                bumblebee=SystemGate.from_value(systems_data.get("bumblebee", True)),
                license=SystemGate.from_value(systems_data.get("license", True)),
            ),
            license=LicenseConfig(
                ecosystems=license_data.get("ecosystems", ["npm", "python", "java"]),
                install=license_data.get("install", {}),
                policy=LicensePolicy(
                    deny=list(policy_data.get("deny", [])),
                    deny_unknown=bool(policy_data.get("deny_unknown", False)),
                    overrides={
                        str(k).strip().lower(): str(v).strip()
                        for k, v in (policy_data.get("overrides", {}) or {}).items()
                    },
                ),
            ),
            python=PythonConfig(
                require_uv_lock=_as_bool(python_data.get("require_uv_lock", False)),
                lock_exclude=[str(p) for p in lock_exclude],
            ),
            paths=paths_data,
        )

    @classmethod
    def _defaults(cls) -> "RepoConfig":
        return cls(email=EmailConfig(to=[]))

    @property
    def scan_root(self) -> str:
        return self.paths.get("scan_root", ".")
