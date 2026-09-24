"""Unit tests for Linux primitives using monkeypatched paths/subprocess
calls, so they run on any platform/CI runner without a real Linux system.
See docs/TEST_MATRIX.md for what was instead verified live in a
disposable, privileged Ubuntu 24.04 Docker container.
"""

import os

import pytest

import auditforge.controls.linux.primitives as linprim
from auditforge.core.models import ChangeRecord
from auditforge.utils.safe_exec import CommandResult


class FakeRunner:
    """Records every invocation and returns a scripted CommandResult."""

    def __init__(self):
        self.calls = []
        self.responses = {}  # argv[0] (or full tuple) -> CommandResult

    def __call__(self, argv, timeout=20, input_text=None):
        self.calls.append(tuple(argv))
        key = tuple(argv)
        if key in self.responses:
            return self.responses[key]
        for prefix, response in self.responses.items():
            if key[: len(prefix)] == prefix:
                return response
        return CommandResult(argv=key, returncode=0, stdout="", stderr="")


@pytest.fixture
def fake_sysctl_dropin(tmp_path, monkeypatch):
    dropin = tmp_path / "90-auditforge.conf"
    monkeypatch.setattr(linprim, "AF_SYSCTL_DROPIN", str(dropin))
    return dropin


@pytest.fixture
def fake_runner(monkeypatch):
    runner = FakeRunner()
    monkeypatch.setattr(linprim, "run", runner)
    monkeypatch.setattr(linprim, "resolve_binary", lambda name: f"/usr/bin/{name}")
    return runner


class TestSysctlPrimitive:
    def test_probe_parses_integer_value(self, fake_runner):
        fake_runner.responses[("/usr/bin/sysctl", "-n", "net.ipv4.ip_forward")] = CommandResult(
            argv=(), returncode=0, stdout="1\n", stderr=""
        )
        prim = linprim.SysctlPrimitive()
        result = prim.probe({"key": "net.ipv4.ip_forward"})
        assert result.value == 1
        assert result.error is None

    def test_probe_error_when_key_unreadable(self, fake_runner):
        fake_runner.responses[("/usr/bin/sysctl", "-n", "net.ipv4.ip_forward")] = CommandResult(
            argv=(), returncode=1, stdout="", stderr="sysctl: unknown key"
        )
        prim = linprim.SysctlPrimitive()
        result = prim.probe({"key": "net.ipv4.ip_forward"})
        assert result.value is None
        assert result.error is not None

    def test_apply_writes_dropin_and_sets_runtime(self, fake_runner, fake_sysctl_dropin):
        fake_runner.responses[("/usr/bin/sysctl", "-n", "net.ipv4.ip_forward")] = CommandResult(
            argv=(), returncode=0, stdout="1\n", stderr=""
        )
        prim = linprim.SysctlPrimitive()
        outcome = prim.apply({"key": "net.ipv4.ip_forward", "value": 0}, expected_value=0)
        assert outcome.previous_value == 1
        assert outcome.new_value == 0
        content = fake_sysctl_dropin.read_text()
        assert "net.ipv4.ip_forward = 0" in content
        assert ("/usr/bin/sysctl", "-w", "net.ipv4.ip_forward=0") in fake_runner.calls

    def test_apply_is_idempotent_single_line_in_dropin(self, fake_runner, fake_sysctl_dropin):
        fake_runner.responses[("/usr/bin/sysctl", "-n", "net.ipv4.ip_forward")] = CommandResult(
            argv=(), returncode=0, stdout="1\n", stderr=""
        )
        prim = linprim.SysctlPrimitive()
        for _ in range(3):
            prim.apply({"key": "net.ipv4.ip_forward", "value": 0}, expected_value=0)
        lines = [l for l in fake_sysctl_dropin.read_text().splitlines() if l.strip()]
        assert lines == ["net.ipv4.ip_forward = 0"]

    def test_rollback_removes_dropin_entry(self, fake_runner, fake_sysctl_dropin):
        fake_sysctl_dropin.write_text("net.ipv4.ip_forward = 0\n")
        prim = linprim.SysctlPrimitive()
        change = ChangeRecord(
            control_id="AF-TEST", primitive="linux_sysctl", params={"key": "net.ipv4.ip_forward"},
            previous_value=1, new_value=0, timestamp="now",
        )
        assert prim.rollback({"key": "net.ipv4.ip_forward"}, change) is True
        assert "net.ipv4.ip_forward" not in fake_sysctl_dropin.read_text()
        assert ("/usr/bin/sysctl", "-w", "net.ipv4.ip_forward=1") in fake_runner.calls


class TestLoginDefsPrimitive:
    @pytest.fixture
    def fake_login_defs(self, tmp_path, monkeypatch):
        path = tmp_path / "login.defs"
        path.write_text("PASS_MAX_DAYS\t99999\nUMASK\t022\n")
        monkeypatch.setattr(linprim, "LOGIN_DEFS", str(path))
        return path

    def test_probe_existing_key(self, fake_login_defs):
        prim = linprim.LoginDefsPrimitive()
        result = prim.probe({"key": "PASS_MAX_DAYS"})
        assert result.value == 99999

    def test_probe_missing_key_uses_default(self, fake_login_defs):
        prim = linprim.LoginDefsPrimitive()
        result = prim.probe({"key": "DOES_NOT_EXIST", "default_if_absent": 42})
        assert result.value == 42

    def test_apply_updates_existing_line_in_place(self, fake_login_defs):
        prim = linprim.LoginDefsPrimitive()
        outcome = prim.apply({"key": "PASS_MAX_DAYS", "value": 90}, expected_value=90)
        assert outcome.previous_value == 99999
        text = fake_login_defs.read_text()
        assert "PASS_MAX_DAYS\t90" in text
        assert "UMASK\t022" in text  # untouched
        assert text.count("PASS_MAX_DAYS") == 1

    def test_apply_appends_new_key_if_absent(self, fake_login_defs):
        prim = linprim.LoginDefsPrimitive()
        prim.apply({"key": "NEW_KEY", "value": 1}, expected_value=1)
        assert "NEW_KEY\t1" in fake_login_defs.read_text()

    def test_rollback_restores_previous_value(self, fake_login_defs):
        prim = linprim.LoginDefsPrimitive()
        outcome = prim.apply({"key": "PASS_MAX_DAYS", "value": 90}, expected_value=90)
        change = ChangeRecord(
            control_id="AF-TEST", primitive="linux_login_defs", params={"key": "PASS_MAX_DAYS"},
            previous_value=outcome.previous_value, new_value=outcome.new_value, timestamp="now",
        )
        prim.rollback({"key": "PASS_MAX_DAYS"}, change)
        assert "PASS_MAX_DAYS\t99999" in fake_login_defs.read_text()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are meaningless on Windows/NTFS")
class TestFilePermissionsPrimitive:
    def test_probe_reports_octal_mode(self, tmp_path):
        f = tmp_path / "shadow"
        f.write_text("secret")
        os.chmod(f, 0o640)
        prim = linprim.FilePermissionsPrimitive()
        result = prim.probe({"path": str(f)})
        assert result.value == "640"

    def test_probe_not_applicable_when_missing(self, tmp_path):
        prim = linprim.FilePermissionsPrimitive()
        result = prim.probe({"path": str(tmp_path / "nope")})
        assert result.not_applicable is True

    def test_apply_and_rollback(self, tmp_path):
        f = tmp_path / "passwd"
        f.write_text("data")
        os.chmod(f, 0o666)
        prim = linprim.FilePermissionsPrimitive()
        outcome = prim.apply({"path": str(f), "value": "644"}, expected_value="644")
        assert oct(os.stat(f).st_mode & 0o777) == "0o644"
        change = ChangeRecord(
            control_id="AF-TEST", primitive="linux_file_permissions", params={"path": str(f)},
            previous_value=outcome.previous_value, new_value=outcome.new_value, timestamp="now",
        )
        assert prim.rollback({"path": str(f)}, change) is True
        assert oct(os.stat(f).st_mode & 0o777) == "0o666"


class TestSudoersNopasswdScan:
    def test_always_reports_manual_review_never_pass_fail(self):
        # /etc/sudoers(.d) won't exist on a non-Linux CI runner; the
        # primitive must degrade gracefully (0 hits) rather than error,
        # and this is a MANUAL_REVIEW-only control regardless of count --
        # see AF-LNX-AUTH-005's rationale (never auto-edit sudoers).
        prim = linprim.SudoersNopasswdScanPrimitive()
        result = prim.probe({})
        assert result.manual_review is True
        assert result.error is None
        assert isinstance(result.value, int)
