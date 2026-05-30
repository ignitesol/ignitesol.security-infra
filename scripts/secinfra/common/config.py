"""Load and validate the per-repo .security/config.yml."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class EmailConfig:
    to: list[str]
    cc: list[str] = field(default_factory=list)

    def all_recipients(self, security_cc: str) -> list[str]:
        """Return To list; security_cc is always included in Cc."""
        return self.to


@dataclass
class LicenseConfig:
    ecosystems: list[str] = field(default_factory=lambda: ["npm", "python", "java"])
    install: dict[str, str] = field(default_factory=dict)


@dataclass
class SystemsConfig:
    security: bool = True
    bumblebee: bool = True
    license: bool = True


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

        return cls(
            email=EmailConfig(to=to_list),
            systems=SystemsConfig(
                security=systems_data.get("security", True),
                bumblebee=systems_data.get("bumblebee", True),
                license=systems_data.get("license", True),
            ),
            license=LicenseConfig(
                ecosystems=license_data.get("ecosystems", ["npm", "python", "java"]),
                install=license_data.get("install", {}),
            ),
            paths=paths_data,
        )

    @classmethod
    def _defaults(cls) -> "RepoConfig":
        return cls(email=EmailConfig(to=[]))

    @property
    def scan_root(self) -> str:
        return self.paths.get("scan_root", ".")
