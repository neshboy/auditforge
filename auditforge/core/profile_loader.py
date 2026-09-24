"""Loads profiles/*.yml into Profile objects used by the harden pipeline."""

from __future__ import annotations

import dataclasses
import os

import yaml

from auditforge.core.paths import profiles_dir


@dataclasses.dataclass
class Profile:
    name: str
    display_name: str
    description: str
    allow_high_impact: bool = False
    audit_only: bool = False
    exclude_categories: tuple = ()
    exclude_controls: tuple = ()
    severity_floor: str = "info"
    notes: str = ""


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_profile(name: str) -> Profile:
    path = os.path.join(profiles_dir(), f"{name}.yml")
    if not os.path.isfile(path):
        available = sorted(f[:-4] for f in os.listdir(profiles_dir()) if f.endswith(".yml"))
        raise FileNotFoundError(f"no profile named '{name}'; available profiles: {available}")
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Profile(
        name=data["name"],
        display_name=data.get("display_name", data["name"]),
        description=data.get("description", ""),
        allow_high_impact=bool(data.get("allow_high_impact", False)),
        audit_only=bool(data.get("audit_only", False)),
        exclude_categories=tuple(data.get("exclude_categories", [])),
        exclude_controls=tuple(data.get("exclude_controls", [])),
        severity_floor=data.get("severity_floor", "info"),
        notes=data.get("notes", ""),
    )


def apply_profile_filter(controls: list, profile: Profile) -> list:
    floor = _SEVERITY_RANK.get(profile.severity_floor, 0)
    excluded_ids = set(profile.exclude_controls)
    excluded_cats = {c.lower() for c in profile.exclude_categories}
    return [
        c
        for c in controls
        if c.control_id not in excluded_ids
        and c.category.lower() not in excluded_cats
        and _SEVERITY_RANK.get(c.severity.value, 0) >= floor
    ]


def list_profiles() -> list:
    return sorted(f[:-4] for f in os.listdir(profiles_dir()) if f.endswith(".yml"))
