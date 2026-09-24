"""macOS probe/apply primitives.

IMPORTANT (see docs/TEST_MATRIX.md and the final report's Limitations
section): this module has NOT been exercised against real macOS hardware
or a macOS VM in this project -- no Apple hardware was available in the
development environment. It is written from documented `defaults`/CLI
behavior and is intentionally conservative: anything irreversible or
security-critical (FileVault, SIP, Gatekeeper's on/off switch, MDM
enrollment) is audit-only, per section 6 and section 9 of the project spec
and per AuditForge's own "never defeat platform security mechanisms" rule.
Treat every macOS control as needing manual verification before relying on
it -- see docs/CONTROLS.md.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from auditforge.core.registry import ApplyOutcome, Primitive, ProbeResult, register
from auditforge.utils.safe_exec import run, validate_token

_IDENT = r"^[A-Za-z][A-Za-z0-9_.\-]*$"


def _console_user() -> Optional[str]:
    res = run(["/usr/bin/stat", "-f%Su", "/dev/console"], timeout=5)
    user = res.stdout.strip()
    return user if res.ok and user and user != "root" else None


# ---------------------------------------------------------------------------
# `defaults` (macOS preference domains) -- covers both a specific user's
# domain (scope: user, run via `sudo -u <console user> defaults ...`) and
# true system-wide domains stored under /Library/Preferences (scope: system,
# run directly since those files are root-owned).
# ---------------------------------------------------------------------------


def _defaults_read(domain: str, key: str, scope: str, host: bool = False) -> tuple:
    exe = "/usr/bin/defaults"
    host_flag = ["-currentHost"] if host else []
    argv = [exe, *host_flag, "read", domain, key]
    if scope == "user":
        user = _console_user()
        if not user:
            return None, "no non-root console user session detected; cannot read a per-user preference domain"
        res = run(["/usr/bin/sudo", "-u", user, *argv], timeout=10)
    else:
        res = run(argv, timeout=10)
    if not res.ok:
        return None, res.stderr.strip() or "key not set"
    return res.stdout.strip(), None


def _defaults_write(domain: str, key: str, value: str, value_type: str, scope: str, host: bool = False) -> bool:
    exe = "/usr/bin/defaults"
    host_flag = ["-currentHost"] if host else []
    argv = [exe, *host_flag, "write", domain, key, f"-{value_type}", value]
    if scope == "user":
        user = _console_user()
        if not user:
            raise RuntimeError("no non-root console user session detected; cannot write a per-user preference domain")
        res = run(["/usr/bin/sudo", "-u", user, *argv], timeout=10)
    else:
        res = run(argv, timeout=10)
    return res.ok


def _defaults_delete(domain: str, key: str, scope: str, host: bool = False) -> bool:
    exe = "/usr/bin/defaults"
    host_flag = ["-currentHost"] if host else []
    argv = [exe, *host_flag, "delete", domain, key]
    if scope == "user":
        user = _console_user()
        if not user:
            return False
        res = run(["/usr/bin/sudo", "-u", user, *argv], timeout=10)
    else:
        res = run(argv, timeout=10)
    return res.ok


@register
class DefaultsPrimitive(Primitive):
    """Generic `defaults` read/write. params: domain, key, scope
    ("user"|"system"), value_type ("bool"|"int"|"string"), host (bool,
    whether to use `-currentHost`)."""

    name = "macos_defaults"

    def probe(self, params: dict) -> ProbeResult:
        domain = validate_token(params["domain"], r"^[A-Za-z0-9_./\-]+$")
        key = validate_token(params["key"], _IDENT)
        scope = params.get("scope", "system")
        host = bool(params.get("host", False))
        raw, err = _defaults_read(domain, key, scope, host)
        if err:
            default = params.get("default_if_absent")
            if default is not None:
                return ProbeResult(value=default, raw={"used_default": True, "reason": err})
            return ProbeResult(value=None, error=err)
        value: Any = raw
        if raw in ("1", "0") or raw.lower() in ("true", "false", "yes", "no"):
            value = raw in ("1", "true", "yes")
        else:
            try:
                value = int(raw)
            except ValueError:
                value = raw
        return ProbeResult(value=value, source=f"defaults read {domain} {key}")

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        domain = validate_token(params["domain"], r"^[A-Za-z0-9_./\-]+$")
        key = validate_token(params["key"], _IDENT)
        scope = params.get("scope", "system")
        host = bool(params.get("host", False))
        value_type = params.get("value_type", "bool")
        target = params.get("value", expected_value)
        before = self.probe(params)
        literal = "TRUE" if (value_type == "bool" and target) else ("FALSE" if value_type == "bool" else str(target))
        ok = _defaults_write(domain, key, literal, value_type, scope, host)
        if not ok:
            raise RuntimeError(f"defaults write {domain} {key} failed")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        domain = validate_token(params["domain"], r"^[A-Za-z0-9_./\-]+$")
        key = validate_token(params["key"], _IDENT)
        scope = params.get("scope", "system")
        host = bool(params.get("host", False))
        if change.previous_value is None:
            return _defaults_delete(domain, key, scope, host)
        value_type = params.get("value_type", "bool")
        literal = "TRUE" if (value_type == "bool" and change.previous_value) else (
            "FALSE" if value_type == "bool" else str(change.previous_value)
        )
        return _defaults_write(domain, key, literal, value_type, scope, host)


# ---------------------------------------------------------------------------
# launchd services (Screen Sharing, File Sharing, Remote Apple Events, ...)
# ---------------------------------------------------------------------------


@register
class LaunchdServicePrimitive(Primitive):
    """params: label (e.g. 'com.apple.screensharing'), domain (default
    'system')."""

    name = "macos_launchd_service"

    def probe(self, params: dict) -> ProbeResult:
        label = validate_token(params["label"], r"^[A-Za-z0-9_.\-]+$")
        domain = params.get("domain", "system")
        res = run(["/bin/launchctl", "print", f"{domain}/{label}"], timeout=10)
        loaded = res.ok
        return ProbeResult(value=(not loaded), source="launchctl print", raw={"loaded": loaded})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        label = validate_token(params["label"], r"^[A-Za-z0-9_.\-]+$")
        domain = params.get("domain", "system")
        target_disabled = bool(params.get("value", expected_value))
        before = self.probe(params)
        verb = "bootout" if target_disabled else "bootstrap"
        plist = params.get("plist_path", f"/System/Library/LaunchDaemons/{label}.plist")
        if verb == "bootstrap" and os.path.isfile(plist):
            res = run(["/bin/launchctl", "bootstrap", domain, plist], timeout=15)
        else:
            res = run(["/bin/launchctl", verb, f"{domain}/{label}"], timeout=15)
        if not res.ok and "not find" not in (res.stderr or "").lower():
            raise RuntimeError(f"launchctl {verb} {domain}/{label} failed: {res.stderr.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target_disabled)

    def rollback(self, params: dict, change) -> bool:
        label = validate_token(params["label"], r"^[A-Za-z0-9_.\-]+$")
        domain = params.get("domain", "system")
        was_disabled = bool(change.previous_value)
        verb = "bootout" if was_disabled else "bootstrap"
        plist = params.get("plist_path", f"/System/Library/LaunchDaemons/{label}.plist")
        if verb == "bootstrap" and os.path.isfile(plist):
            res = run(["/bin/launchctl", "bootstrap", domain, plist], timeout=15)
        else:
            res = run(["/bin/launchctl", verb, f"{domain}/{label}"], timeout=15)
        return res.ok


# ---------------------------------------------------------------------------
# Narrow, well-known CLI status commands -- audit-only where irreversible
# or security-critical, per project spec section 9.
# ---------------------------------------------------------------------------


@register
class FileVaultStatusPrimitive(Primitive):
    """Audit-only by design: never auto-enable disk encryption without a
    recovery-key escrow plan (project spec section 6)."""

    name = "macos_fdesetup_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run(["/usr/bin/fdesetup", "status"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "fdesetup status failed")
        on = "FileVault is On" in res.stdout
        return ProbeResult(value=on, source="fdesetup status", raw={"raw": res.stdout.strip()})


@register
class SipStatusPrimitive(Primitive):
    """Audit-only by design: AuditForge never bypasses or attempts to
    change System Integrity Protection (requires Recovery OS + explicitly
    contradicts the project's 'do not defeat platform security' rule)."""

    name = "macos_csrutil_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run(["/usr/bin/csrutil", "status"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "csrutil status failed")
        enabled = "enabled" in res.stdout.lower()
        return ProbeResult(value=enabled, source="csrutil status", raw={"raw": res.stdout.strip()})


@register
class GatekeeperStatusPrimitive(Primitive):
    """Audit-only: unverified/inconsistent CLI toggle behavior across macOS
    versions in available documentation (see docs/SOURCES.md Apple
    section); safer to report only, matching the FileVault/SIP posture."""

    name = "macos_spctl_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run(["/usr/sbin/spctl", "--status"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "spctl --status failed")
        enabled = "assessments enabled" in res.stdout.lower()
        return ProbeResult(value=enabled, source="spctl --status", raw={"raw": res.stdout.strip()})


@register
class ApplicationFirewallStatePrimitive(Primitive):
    name = "macos_alf_state"

    def probe(self, params: dict) -> ProbeResult:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        res = run([exe, "--getglobalstate"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "socketfilterfw failed")
        enabled = "enabled" in res.stdout.lower() and "disabled" not in res.stdout.lower()
        return ProbeResult(value=enabled, source="socketfilterfw --getglobalstate", raw={"raw": res.stdout.strip()})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        target = bool(params.get("value", expected_value))
        before = self.probe(params)
        res = run([exe, "--setglobalstate", "on" if target else "off"], timeout=10)
        if not res.ok:
            raise RuntimeError(f"socketfilterfw --setglobalstate failed: {res.stderr.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        res = run([exe, "--setglobalstate", "on" if change.previous_value else "off"], timeout=10)
        return res.ok


@register
class ApplicationFirewallStealthPrimitive(Primitive):
    name = "macos_alf_stealth"

    def probe(self, params: dict) -> ProbeResult:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        res = run([exe, "--getstealthmode"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "socketfilterfw failed")
        enabled = "enabled" in res.stdout.lower()
        return ProbeResult(value=enabled, source="socketfilterfw --getstealthmode", raw={"raw": res.stdout.strip()})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        target = bool(params.get("value", expected_value))
        before = self.probe(params)
        res = run([exe, "--setstealthmode", "on" if target else "off"], timeout=10)
        if not res.ok:
            raise RuntimeError(f"socketfilterfw --setstealthmode failed: {res.stderr.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        res = run([exe, "--setstealthmode", "on" if change.previous_value else "off"], timeout=10)
        return res.ok


_SYSTEMSETUP_FLAGS = {"remotelogin", "remoteappleevents"}


@register
class SystemsetupFlagPrimitive(Primitive):
    """Generic on/off flag via `systemsetup -get<flag>` / `-set<flag>`.
    params: flag (one of _SYSTEMSETUP_FLAGS, e.g. 'remotelogin' for SSH,
    'remoteappleevents' for Remote Apple Events)."""

    name = "macos_systemsetup_flag"

    def probe(self, params: dict) -> ProbeResult:
        flag = params["flag"]
        if flag not in _SYSTEMSETUP_FLAGS:
            raise ValueError(f"unsupported systemsetup flag '{flag}'")
        res = run(["/usr/sbin/systemsetup", f"-get{flag}"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "systemsetup failed (may require sudo)")
        enabled = "on" in res.stdout.lower()
        return ProbeResult(value=enabled, source=f"systemsetup -get{flag}", raw={"raw": res.stdout.strip()})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        flag = params["flag"]
        if flag not in _SYSTEMSETUP_FLAGS:
            raise ValueError(f"unsupported systemsetup flag '{flag}'")
        target = bool(params.get("value", expected_value))
        before = self.probe(params)
        res = run(["/usr/sbin/systemsetup", f"-set{flag}", "on" if target else "off"], timeout=15)
        if not res.ok:
            raise RuntimeError(f"systemsetup -set{flag} failed: {res.stderr.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        flag = params["flag"]
        res = run(["/usr/sbin/systemsetup", f"-set{flag}", "on" if change.previous_value else "off"], timeout=15)
        return res.ok


@register
class MdmEnrollmentStatusPrimitive(Primitive):
    """Audit-only: reports MDM enrollment for report visibility (also
    surfaced via ManagementInfo)."""

    name = "macos_profiles_enrollment"

    def probe(self, params: dict) -> ProbeResult:
        res = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=15)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or "profiles status failed")
        enrolled = "MDM enrollment: Yes" in res.stdout
        return ProbeResult(value=enrolled, source="profiles status -type enrollment", raw={"raw": res.stdout.strip()})
