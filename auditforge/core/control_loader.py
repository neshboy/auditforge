"""Loads and validates controls/<os>/*.yml into ControlDefinition objects.

Every control file is validated against CONTROL_SCHEMA before it is trusted,
so a malformed or malicious control file fails loudly at load time instead
of being partially interpreted (see the "malicious configuration files"
threat listed in docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import glob
import os
from typing import Iterable

import yaml
from jsonschema import Draft202012Validator

from auditforge.core.models import ControlDefinition, FrameworkMapping, OperatingSystem, Severity

CONTROL_SCHEMA = {
    "type": "object",
    "required": [
        "control_id",
        "title",
        "description",
        "os",
        "category",
        "severity",
        "benchmark",
        "rationale",
        "audit",
        "expected_value",
    ],
    "properties": {
        "control_id": {"type": "string", "pattern": r"^AF-(WIN|LNX|MAC)-[A-Z0-9]+-\d{3}$"},
        "title": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "os": {"type": "string", "enum": ["windows", "linux", "macos"]},
        "applies_to": {"type": "array", "items": {"type": "string"}},
        "category": {"type": "string"},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "benchmark": {"type": "string"},
        "benchmark_version": {"type": "string"},
        "external_reference": {"type": "string"},
        "rationale": {"type": "string"},
        "audit": {
            "type": "object",
            "required": ["primitive", "params"],
            "properties": {
                "primitive": {"type": "string"},
                "params": {"type": "object"},
            },
        },
        "remediation": {
            "type": ["object", "null"],
            "properties": {
                "primitive": {"type": "string"},
                "params": {"type": "object"},
                "reboot_required": {"type": "boolean"},
                "service_restart_required": {"type": "boolean"},
            },
        },
        "expected_value": {},
        "possible_impact": {"type": "string"},
        "frameworks": {"type": "object"},
        "management_detection": {"type": "boolean"},
        "high_impact": {"type": "boolean"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string"},
    },
    "additionalProperties": False,
}

_validator = Draft202012Validator(CONTROL_SCHEMA)


class ControlValidationError(ValueError):
    pass


def load_control_file(path: str) -> ControlDefinition:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ControlValidationError(f"{path}: control file must contain a single YAML mapping")

    errors = sorted(_validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        details = "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
        raise ControlValidationError(f"{path}: schema validation failed: {details}")

    remediation = data.get("remediation")
    return ControlDefinition(
        control_id=data["control_id"],
        title=data["title"],
        description=data["description"],
        os=OperatingSystem(data["os"]),
        applies_to=tuple(data.get("applies_to", ["all"])),
        category=data["category"],
        severity=Severity(data["severity"]),
        benchmark=data["benchmark"],
        benchmark_version=data.get("benchmark_version", ""),
        external_reference=data.get("external_reference", ""),
        rationale=data["rationale"],
        audit=data["audit"],
        remediation=remediation,
        expected_value=data["expected_value"],
        possible_impact=data.get("possible_impact", ""),
        frameworks=FrameworkMapping.from_dict(data.get("frameworks")),
        management_detection=bool(data.get("management_detection", False)),
        high_impact=bool(data.get("high_impact", False)),
        tags=tuple(data.get("tags", [])),
        notes=data.get("notes", ""),
        source_file=path,
    )


def load_controls_dir(directory: str) -> list[ControlDefinition]:
    controls: list[ControlDefinition] = []
    seen_ids: dict[str, str] = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.yml"))):
        control = load_control_file(path)
        if control.control_id in seen_ids:
            raise ControlValidationError(
                f"duplicate control_id {control.control_id} in {path} "
                f"(already defined in {seen_ids[control.control_id]})"
            )
        seen_ids[control.control_id] = path
        controls.append(control)
    return controls


def load_controls_for_os(os_name: OperatingSystem, base_dir: str) -> list[ControlDefinition]:
    directory = os.path.join(base_dir, "controls", os_name.value)
    return load_controls_dir(directory)


def filter_by_ids(controls: Iterable[ControlDefinition], ids: Iterable[str]) -> list[ControlDefinition]:
    wanted = set(ids)
    return [c for c in controls if c.control_id in wanted]


def filter_by_categories(controls: Iterable[ControlDefinition], categories: Iterable[str]) -> list[ControlDefinition]:
    wanted = {c.lower() for c in categories}
    return [c for c in controls if c.category.lower() in wanted]
