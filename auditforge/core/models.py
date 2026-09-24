"""Core data model shared by every OS module: statuses, severities, control
definitions, and the result/evidence objects produced by a run.

Design note (documented in docs/ARCHITECTURE.md): the master spec lists
REMEDIATION_AVAILABLE alongside PASS/FAIL/... as if it were a status value.
We treat it as a boolean attribute of a finding instead, because a control
can simultaneously be e.g. FAIL *and* remediable, or FAIL and NOT remediable
(manual-only) -- collapsing that into one enum would lose information the
HTML report needs to show (see the "Remediation Available: YES" line in the
spec's own sample report).
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Optional


class Status(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    MANAGED_BY_ORGANIZATION = "MANAGED_BY_ORGANIZATION"
    ERROR = "ERROR"  # probe itself failed (permissions, missing tool, etc.)

    @property
    def is_finding(self) -> bool:
        """Whether this status represents something worth counting as a gap."""
        return self in (Status.FAIL, Status.WARNING)


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class OperatingSystem(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


@dataclasses.dataclass(frozen=True)
class FrameworkMapping:
    """Cross-references from one control to one or more compliance frameworks.

    Values are our own control-ID-level references to the authoritative
    document; we never store copied benchmark description text here.
    """

    nist_800_53: tuple[str, ...] = ()
    nist_800_171: tuple[str, ...] = ()
    nist_800_63b: tuple[str, ...] = ()
    disa_stig: tuple[str, ...] = ()
    cis: tuple[str, ...] = ()
    microsoft_baseline: tuple[str, ...] = ()
    apple_guidance: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> FrameworkMapping:
        data = data or {}

        def _tup(key: str) -> tuple:
            v = data.get(key) or ()
            return tuple(v) if isinstance(v, (list, tuple)) else (v,)

        return cls(
            nist_800_53=_tup("nist_800_53"),
            nist_800_171=_tup("nist_800_171"),
            nist_800_63b=_tup("nist_800_63b"),
            disa_stig=_tup("disa_stig"),
            cis=_tup("cis"),
            microsoft_baseline=_tup("microsoft_baseline"),
            apple_guidance=_tup("apple_guidance"),
        )


@dataclasses.dataclass(frozen=True)
class ControlDefinition:
    """The parsed, validated contents of one controls/<os>/*.yml file."""

    control_id: str
    title: str
    description: str
    os: OperatingSystem
    applies_to: tuple[str, ...]
    category: str
    severity: Severity
    benchmark: str
    benchmark_version: str
    external_reference: str
    rationale: str
    audit: dict  # {"primitive": str, "params": {...}}
    remediation: Optional[dict]  # {"primitive": str, "params": {...}, "reboot_required": bool, ...}
    expected_value: str
    possible_impact: str
    frameworks: FrameworkMapping
    management_detection: bool = False
    high_impact: bool = False
    tags: tuple[str, ...] = ()
    notes: str = ""
    source_file: str = ""

    @property
    def remediation_available(self) -> bool:
        return bool(self.remediation)

    @property
    def reboot_required(self) -> bool:
        return bool(self.remediation and self.remediation.get("reboot_required"))

    @property
    def service_restart_required(self) -> bool:
        return bool(self.remediation and self.remediation.get("service_restart_required"))


@dataclasses.dataclass
class Evidence:
    """Redacted, structured proof backing a single control result."""

    detected_value: Any
    expected_value: Any
    source: str
    timestamp: str
    raw: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "detected_value": self.detected_value,
            "expected_value": self.expected_value,
            "source": self.source,
            "timestamp": self.timestamp,
            "raw": self.raw or {},
        }


@dataclasses.dataclass
class ControlResult:
    """The outcome of auditing (and optionally remediating) one control."""

    control: ControlDefinition
    status: Status
    evidence: Evidence
    message: str = ""
    remediation_applied: bool = False
    remediation_status: Optional[str] = None  # "applied" | "failed" | "skipped" | "dry_run"
    error: Optional[str] = None

    def to_dict(self) -> dict:
        c = self.control
        return {
            "control_id": c.control_id,
            "title": c.title,
            "description": c.description,
            "os": c.os.value,
            "category": c.category,
            "severity": c.severity.value,
            "benchmark": c.benchmark,
            "benchmark_version": c.benchmark_version,
            "external_reference": c.external_reference,
            "rationale": c.rationale,
            "expected_value": c.expected_value,
            "possible_impact": c.possible_impact,
            "reboot_required": c.reboot_required,
            "service_restart_required": c.service_restart_required,
            "remediation_available": c.remediation_available,
            "status": self.status.value,
            "message": self.message,
            "evidence": self.evidence.to_dict(),
            "remediation_applied": self.remediation_applied,
            "remediation_status": self.remediation_status,
            "error": self.error,
            "frameworks": dataclasses.asdict(c.frameworks),
        }


@dataclasses.dataclass
class ChangeRecord:
    """One row of a rollback transaction: what changed and how to undo it."""

    control_id: str
    primitive: str
    params: dict
    previous_value: Any
    new_value: Any
    timestamp: str
    backup_file: Optional[str] = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)
