import pytest

from auditforge.utils.safe_exec import UnsafeValueError, validate_token, run


class TestValidateToken:
    def test_accepts_normal_identifiers(self):
        assert validate_token("EnableScriptBlockLogging") == "EnableScriptBlockLogging"
        assert validate_token("net.ipv4.ip_forward", r"^[a-z][a-z0-9_.]*$") == "net.ipv4.ip_forward"

    def test_rejects_shell_metacharacters(self):
        for payload in ["value; rm -rf /", "$(whoami)", "`id`", "a|b", "a&&b", "a\nb"]:
            with pytest.raises(UnsafeValueError):
                validate_token(payload)

    def test_rejects_powershell_injection_attempt(self):
        with pytest.raises(UnsafeValueError):
            validate_token("Enabled'; Remove-Item C:\\Windows -Recurse; '")

    def test_rejects_none(self):
        with pytest.raises(UnsafeValueError):
            validate_token(None)

    def test_custom_pattern_is_honored(self):
        with pytest.raises(UnsafeValueError):
            validate_token("not_matching_custom_pattern", r"^[0-9]+$")
        assert validate_token("12345", r"^[0-9]+$") == "12345"


class TestRun:
    def test_run_never_uses_shell(self):
        # A payload that would be dangerous under shell=True must be
        # treated as a single literal argument, not shell-interpreted.
        import sys

        result = run([sys.executable, "-c", "print('$(whoami); rm -rf /')"])
        assert result.ok
        assert "$(whoami); rm -rf /" in result.stdout

    def test_run_missing_binary_reports_failure_not_exception(self):
        result = run(["this-binary-does-not-exist-anywhere"])
        assert not result.ok

    def test_run_respects_timeout(self):
        import sys

        result = run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        assert result.timed_out
        assert not result.ok
