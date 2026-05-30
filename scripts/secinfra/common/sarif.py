"""Normalize SARIF 2.1 and tool-specific JSON into a common Finding model."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, s: str | None) -> "Severity":
        mapping = {
            "critical": cls.CRITICAL,
            "error": cls.HIGH,
            "high": cls.HIGH,
            "warning": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "note": cls.LOW,
            "low": cls.LOW,
            "info": cls.INFO,
            "information": cls.INFO,
            "none": cls.INFO,
        }
        return mapping.get((s or "").lower(), cls.UNKNOWN)


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: Severity
    file: str = ""
    line: int = 0
    message: str = ""
    url: str = ""

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or ""


def load_sarif(path: Path, tool: str) -> list[Finding]:
    data = json.loads(path.read_text())
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules: dict[str, Any] = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
            severity = Severity.from_string(level)
            message = result.get("message", {}).get("text", "")
            loc = result.get("locations", [{}])[0]
            phys = loc.get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            reg = phys.get("region", {})
            findings.append(Finding(
                tool=tool,
                rule_id=rule_id,
                title=rule.get("shortDescription", {}).get("text") or rule_id,
                severity=severity,
                file=art.get("uri", ""),
                line=reg.get("startLine", 0),
                message=message,
                url=rule.get("helpUri", ""),
            ))
    return findings


def load_gitleaks_json(path: Path) -> list[Finding]:
    """Parse Gitleaks --report-format json output."""
    data = json.loads(path.read_text())
    if not data:
        return []
    findings = []
    for leak in data:
        findings.append(Finding(
            tool="gitleaks",
            rule_id=leak.get("RuleID", "secret"),
            title=leak.get("Description", "Secret detected"),
            severity=Severity.HIGH,
            file=leak.get("File", ""),
            line=leak.get("StartLine", 0),
            message=f"Match: {leak.get('Match', '')}",
        ))
    return findings


def load_trivy_json(path: Path) -> list[Finding]:
    """Parse Trivy --format json output (fs or config mode)."""
    data = json.loads(path.read_text())
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        # SCA vulnerabilities
        for vuln in result.get("Vulnerabilities", []):
            findings.append(Finding(
                tool="trivy-sca",
                rule_id=vuln.get("VulnerabilityID", ""),
                title=f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} — {vuln.get('VulnerabilityID', '')}",
                severity=Severity.from_string(vuln.get("Severity")),
                file=target,
                message=vuln.get("Title", vuln.get("Description", ""))[:200],
                url=vuln.get("PrimaryURL", ""),
            ))
        # IaC misconfigurations
        for misc in result.get("Misconfigurations", []):
            findings.append(Finding(
                tool="trivy-iac",
                rule_id=misc.get("ID", ""),
                title=misc.get("Title", misc.get("ID", "")),
                severity=Severity.from_string(misc.get("Severity")),
                file=target,
                message=misc.get("Message", ""),
                url=misc.get("PrimaryURL", ""),
            ))
    return findings


_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {k: v for k, v in counts.items() if v > 0}
