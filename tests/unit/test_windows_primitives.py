"""Unit tests for Windows primitives using a fake in-memory `winreg`, so
they run on any platform/CI runner without a real Windows registry.
This is the 'mocked OS states' testing approach called for by the project
spec -- see docs/TEST_MATRIX.md for what was instead verified live against
a real Windows 11 machine.
"""

import pytest

import auditforge.controls.windows.primitives as winprim
from auditforge.core.models import ChangeRecord


class FakeWinreg:
    """Minimal in-memory stand-in for the parts of `winreg` our
    primitives use: HKLM/HKCU hives, REG_DWORD/REG_SZ values."""

    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    REG_DWORD = "DWORD"
    REG_SZ = "SZ"
    KEY_SET_VALUE = 0

    def __init__(self):
        self.store = {}  # (hive, path, name) -> (value, type)

    def OpenKey(self, hive, path, *_args, **_kwargs):
        return FakeKeyContext(self, hive, path)

    def CreateKeyEx(self, hive, path, *_args, **_kwargs):
        return FakeKeyContext(self, hive, path)

    def QueryValueEx(self, key_ctx, name):
        entry = self.store.get((key_ctx.hive, key_ctx.path, name))
        if entry is None:
            raise FileNotFoundError()
        return entry

    def SetValueEx(self, key_ctx, name, _reserved, vtype, value):
        self.store[(key_ctx.hive, key_ctx.path, name)] = (value, vtype)

    def DeleteValue(self, key_ctx, name):
        key = (key_ctx.hive, key_ctx.path, name)
        if key not in self.store:
            raise FileNotFoundError()
        del self.store[key]


class FakeKeyContext:
    def __init__(self, backend, hive, path):
        self.backend = backend
        self.hive = hive
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_winreg(monkeypatch):
    fake = FakeWinreg()
    monkeypatch.setattr(winprim, "winreg", fake)
    monkeypatch.setattr(winprim, "_HIVES", {"HKLM": "HKLM", "HKCU": "HKCU"})
    return fake


class TestRegistryDwordPrimitive:
    def test_probe_reports_default_when_absent(self, fake_winreg):
        prim = winprim.RegistryDwordPrimitive()
        result = prim.probe({"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "default_if_absent": 7})
        assert result.value == 7
        assert result.raw["exists"] is False

    def test_probe_reports_real_value_when_present(self, fake_winreg):
        fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] = (1, "DWORD")
        prim = winprim.RegistryDwordPrimitive()
        result = prim.probe({"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X"})
        assert result.value == 1
        assert result.raw["exists"] is True

    def test_policy_source_detected_for_policies_path(self, fake_winreg):
        prim = winprim.RegistryDwordPrimitive()
        result = prim.probe(
            {"hive": "HKLM", "path": "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", "name": "X"}
        )
        assert "policy_source" in result.raw

    def test_no_policy_source_for_non_policies_path(self, fake_winreg):
        prim = winprim.RegistryDwordPrimitive()
        result = prim.probe({"hive": "HKLM", "path": "SYSTEM\\CurrentControlSet\\Control\\Lsa", "name": "X"})
        assert "policy_source" not in result.raw

    def test_apply_writes_value_and_returns_previous(self, fake_winreg):
        fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] = (0, "DWORD")
        prim = winprim.RegistryDwordPrimitive()
        outcome = prim.apply({"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "value": 1}, expected_value=1)
        assert outcome.previous_value == 0
        assert outcome.new_value == 1
        assert fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] == (1, "DWORD")

    def test_apply_records_absent_sentinel_when_value_did_not_exist(self, fake_winreg):
        prim = winprim.RegistryDwordPrimitive()
        outcome = prim.apply({"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "value": 1}, expected_value=1)
        assert outcome.previous_value == {"__absent__": True}

    def test_rollback_restores_previous_value(self, fake_winreg):
        fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] = (0, "DWORD")
        prim = winprim.RegistryDwordPrimitive()
        params = {"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "value": 1}
        outcome = prim.apply(params, expected_value=1)
        change = ChangeRecord(
            control_id="AF-TEST", primitive="win_registry_dword", params=params,
            previous_value=outcome.previous_value, new_value=outcome.new_value, timestamp="now",
        )
        assert prim.rollback(params, change) is True
        assert fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] == (0, "DWORD")

    def test_rollback_deletes_value_that_did_not_exist_before(self, fake_winreg):
        prim = winprim.RegistryDwordPrimitive()
        params = {"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "value": 1}
        outcome = prim.apply(params, expected_value=1)
        change = ChangeRecord(
            control_id="AF-TEST", primitive="win_registry_dword", params=params,
            previous_value=outcome.previous_value, new_value=outcome.new_value, timestamp="now",
        )
        assert prim.rollback(params, change) is True
        assert ("HKLM", "SOFTWARE\\Test", "X") not in fake_winreg.store

    def test_apply_rollback_is_idempotent(self, fake_winreg):
        fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] = (0, "DWORD")
        prim = winprim.RegistryDwordPrimitive()
        params = {"hive": "HKLM", "path": "SOFTWARE\\Test", "name": "X", "value": 1}
        for _ in range(3):
            outcome = prim.apply(params, expected_value=1)
        assert fake_winreg.store[("HKLM", "SOFTWARE\\Test", "X")] == (1, "DWORD")
        assert outcome.previous_value == 1  # already 1 by the 2nd/3rd run


class TestGuardConnectivity:
    def test_rdp_guard_blocks_apply_during_rdp_session(self, fake_winreg, monkeypatch):
        monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#3")
        prim = winprim.RegistryDwordPrimitive()
        params = {
            "hive": "HKLM",
            "path": "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "name": "fDenyTSConnections",
            "value": 1,
            "guard": "current_session_rdp",
        }
        with pytest.raises(RuntimeError, match="RDP"):
            prim.apply(params, expected_value=1)

    def test_rdp_guard_allows_apply_outside_rdp_session(self, fake_winreg, monkeypatch):
        monkeypatch.delenv("SESSIONNAME", raising=False)
        prim = winprim.RegistryDwordPrimitive()
        params = {
            "hive": "HKLM",
            "path": "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "name": "fDenyTSConnections",
            "value": 1,
            "guard": "current_session_rdp",
        }
        outcome = prim.apply(params, expected_value=1)
        assert outcome.new_value == 1
