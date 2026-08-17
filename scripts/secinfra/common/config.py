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


@dataclass
class LicenseConfig:
    ecosystems: list[str] = field(default_factory=lambda: ["npm", "python", "java"])
    install: dict[str, str] = field(default_factory=dict)
    policy: LicensePolicy = field(default_factory=LicensePolicy)


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
                ),
            ),
            paths=paths_data,
        )

    @classmethod
    def _defaults(cls) -> "RepoConfig":
        return cls(email=EmailConfig(to=[]))

    @property
    def scan_root(self) -> str:
        return self.paths.get("scan_root", ".")
