import pytest

from auditforge.core.control_loader import load_control_file
from auditforge.core.profile_loader import apply_profile_filter, list_profiles, load_profile
import os

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def test_list_profiles_includes_shipped_defaults():
    names = list_profiles()
    for expected in ("audit_only", "workstation", "corporate", "developer", "server", "public_server", "strict"):
        assert expected in names


def test_load_profile_fields():
    profile = load_profile("audit_only")
    assert profile.name == "audit_only"
    assert profile.audit_only is True
    assert profile.allow_high_impact is False


def test_load_unknown_profile_raises():
    with pytest.raises(FileNotFoundError):
        load_profile("does-not-exist")


def test_strict_profile_allows_high_impact():
    profile = load_profile("strict")
    assert profile.allow_high_impact is True


def test_apply_profile_filter_excludes_by_id():
    control = load_control_file(os.path.join(FIXTURES, "valid_control.yml"))
    control = control.__class__(**{**control.__dict__, "control_id": "AF-WIN-ASR-004"})
    profile = load_profile("workstation")
    assert control.control_id in profile.exclude_controls
    filtered = apply_profile_filter([control], profile)
    assert filtered == []


def test_apply_profile_filter_excludes_by_category():
    from auditforge.core.profile_loader import Profile

    control = load_control_file(os.path.join(FIXTURES, "valid_control.yml"))
    profile = Profile(name="x", display_name="X", description="", exclude_categories=("testing",))
    assert apply_profile_filter([control], profile) == []


def test_apply_profile_filter_severity_floor():
    from auditforge.core.profile_loader import Profile

    control = load_control_file(os.path.join(FIXTURES, "valid_control.yml"))
    assert control.severity.value == "medium"
    profile = Profile(name="x", display_name="X", description="", severity_floor="high")
    assert apply_profile_filter([control], profile) == []
    profile2 = Profile(name="x", display_name="X", description="", severity_floor="low")
    assert apply_profile_filter([control], profile2) == [control]
