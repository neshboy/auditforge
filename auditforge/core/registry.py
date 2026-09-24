"""The primitive registry: the fixed, trusted vocabulary of probe/apply
operations that control YAML files are allowed to reference.

This is the safety boundary described in docs/ARCHITECTURE.md: a control
file can only say "use primitive X with these parameters" -- it can never
supply a command or script to execute. Every primitive is engine code,
reviewed like any other source file, not user/control-supplied text.
"""

from __future__ import annotations

import abc
import dataclasses
from typing import Any, ClassVar, Optional


@dataclasses.dataclass
class ProbeResult:
    value: Any
    raw: dict = dataclasses.field(default_factory=dict)
    source: str = ""
    error: Optional[str] = None
    not_applicable: bool = False
    not_applicable_reason: str = ""
    manual_review: bool = False
    manual_review_reason: str = ""


@dataclasses.dataclass
class ApplyOutcome:
    previous_value: Any
    new_value: Any
    backup_file: Optional[str] = None
    notes: str = ""
    changed: bool = True


def compare_value(detected: Any, expected: Any) -> bool:
    """Shared PASS/FAIL comparison used by every primitive's default
    compare(). Supports plain equality plus a small expected_value
    mini-language for numeric/set semantics, e.g.:
        expected_value: {"max": 3}       # detected <= 3
        expected_value: {"min": 14}      # detected >= 14
        expected_value: {"one_of": [...]}
        expected_value: {"not": "Enabled"}
    """
    if isinstance(expected, dict):
        if "one_of" in expected:
            return detected in expected["one_of"]
        if "not" in expected and "min" not in expected and "max" not in expected:
            return detected != expected["not"]
        if "min" in expected or "max" in expected:
            try:
                numeric = float(detected)
            except (TypeError, ValueError):
                return False
            if "min" in expected and numeric < float(expected["min"]):
                return False
            if "max" in expected and numeric > float(expected["max"]):
                return False
            return True
        return detected == expected
    if isinstance(expected, bool) or isinstance(detected, bool):
        return bool(detected) == bool(expected)
    if isinstance(expected, str) and isinstance(detected, str):
        return detected.strip().lower() == expected.strip().lower()
    return detected == expected


class Primitive(abc.ABC):
    """Base class for one probe/apply/rollback capability, e.g. 'a Windows
    registry DWORD' or 'an sshd_config option'. Concrete primitives live in
    auditforge/controls/<os>/primitives.py.
    """

    name: ClassVar[str] = ""

    @abc.abstractmethod
    def probe(self, params: dict) -> ProbeResult:
        """Read current state. Must never modify the system."""
        raise NotImplementedError

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        raise NotImplementedError(f"primitive '{self.name}' is audit-only; no remediation implemented")

    def rollback(self, params: dict, change: ChangeRecordLike) -> bool:
        raise NotImplementedError(f"primitive '{self.name}' does not support rollback")

    def compare(self, detected: Any, expected: Any) -> bool:
        """Default PASS/FAIL comparison; override for primitive-specific
        semantics. Most primitives can rely on this default."""
        return compare_value(detected, expected)


class ChangeRecordLike:
    """Structural type hint only; the real dataclass lives in core.models."""


_REGISTRY: dict[str, Primitive] = {}


def register(primitive_or_cls):
    """Decorator: registers a Primitive instance, or a Primitive subclass
    (in which case it is instantiated with no args). Used as `@register`
    directly on a class definition throughout controls/<os>/primitives.py."""
    primitive = primitive_or_cls() if isinstance(primitive_or_cls, type) else primitive_or_cls
    if not primitive.name:
        raise ValueError(f"primitive {primitive.__class__.__name__} must set a non-empty 'name'")
    if primitive.name in _REGISTRY:
        raise ValueError(f"duplicate primitive name: {primitive.name}")
    _REGISTRY[primitive.name] = primitive
    return primitive_or_cls


def get(name: str) -> Primitive:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown primitive '{name}' -- control YAML references a primitive "
            f"the engine does not implement. Known: {sorted(_REGISTRY)}"
        ) from exc


def all_names() -> list[str]:
    return sorted(_REGISTRY)


def is_registered(name: str) -> bool:
    return name in _REGISTRY
