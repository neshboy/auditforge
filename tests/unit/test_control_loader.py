import os

import pytest

from auditforge.core.control_loader import (
    ControlValidationError,
    filter_by_categories,
    filter_by_ids,
    load_control_file,
    load_controls_dir,
    load_controls_for_os,
)
from auditforge.core.models import OperatingSystem
from auditforge.core.paths import controls_base_dir

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")
CONTROLS_BASE = controls_base_dir()


def test_load_valid_control():
    control = load_control_file(os.path.join(FIXTURES, "valid_control.yml"))
    assert control.control_id == "AF-WIN-TST-001"
    assert control.severity.value == "medium"
    assert control.remediation is None
    assert control.remediation_available is False


@pytest.mark.parametrize(
    "fixture",
    [
        "invalid_control_missing_field.yml",
        "invalid_control_bad_id.yml",
        "invalid_control_unknown_field.yml",
    ],
)
def test_invalid_controls_rejected(fixture):
    with pytest.raises(ControlValidationError):
        load_control_file(os.path.join(FIXTURES, fixture))


def test_duplicate_control_id_rejected(tmp_path):
    content = open(os.path.join(FIXTURES, "valid_control.yml"), encoding="utf-8").read()
    (tmp_path / "a.yml").write_text(content, encoding="utf-8")
    (tmp_path / "b.yml").write_text(content, encoding="utf-8")
    with pytest.raises(ControlValidationError, match="duplicate"):
        load_controls_dir(str(tmp_path))


def test_filter_by_ids():
    controls = [load_control_file(os.path.join(FIXTURES, "valid_control.yml"))]
    wanted = filter_by_ids(controls, ["AF-WIN-TST-001"])
    assert [c.control_id for c in wanted] == ["AF-WIN-TST-001"]
    assert filter_by_ids(controls, ["AF-DOES-NOT-EXIST-001"]) == []


def test_filter_by_categories():
    controls = [load_control_file(os.path.join(FIXTURES, "valid_control.yml"))]
    wanted = filter_by_categories(controls, ["testing"])
    assert len(wanted) == 1
    assert filter_by_categories(controls, ["nonexistent"]) == []


class TestShippedControls:
    """Every control file actually shipped in the repo must parse and
    validate cleanly -- this is the guardrail against a typo in any of
    the 100+ real control YAML files silently breaking the product."""

    def test_windows_controls_load(self):
        controls = load_controls_for_os(OperatingSystem.WINDOWS, CONTROLS_BASE)
        assert len(controls) >= 40
        ids = [c.control_id for c in controls]
        assert len(ids) == len(set(ids)), "duplicate control_id across shipped Windows controls"

    def test_linux_controls_load(self):
        controls = load_controls_for_os(OperatingSystem.LINUX, CONTROLS_BASE)
        assert len(controls) >= 30
        ids = [c.control_id for c in controls]
        assert len(ids) == len(set(ids)), "duplicate control_id across shipped Linux controls"

    def test_macos_controls_load(self):
        controls = load_controls_for_os(OperatingSystem.MACOS, CONTROLS_BASE)
        assert len(controls) >= 10
        ids = [c.control_id for c in controls]
        assert len(ids) == len(set(ids)), "duplicate control_id across shipped macOS controls"

    @pytest.mark.parametrize("os_enum", [OperatingSystem.WINDOWS, OperatingSystem.LINUX, OperatingSystem.MACOS])
    def test_every_shipped_control_references_a_registered_primitive(self, os_enum):
        import importlib

        module_name = {
            OperatingSystem.WINDOWS: "auditforge.controls.windows.primitives",
            OperatingSystem.LINUX: "auditforge.controls.linux.primitives",
            OperatingSystem.MACOS: "auditforge.controls.macos.primitives",
        }[os_enum]
        importlib.import_module(module_name)
        from auditforge.core import registry

        controls = load_controls_for_os(os_enum, CONTROLS_BASE)
        for c in controls:
            assert registry.is_registered(c.audit["primitive"]), f"{c.control_id}: unknown audit primitive"
            if c.remediation:
                assert registry.is_registered(
                    c.remediation["primitive"]
                ), f"{c.control_id}: unknown remediation primitive"
