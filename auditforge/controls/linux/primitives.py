"""Linux probe/apply primitives.

Design mirrors controls/windows/primitives.py: a fixed, trusted set of
parameterized primitives that controls/linux/*.yml reference by name.
Every primitive that mutates config manages its OWN drop-in file/section
(sysctl.d, sshd_config.d, journald.conf.d) rather than editing distro-owned
files in place, so rollback is exact and other tooling's configuration is
never touched. sudoers is deliberately audit-only everywhere -- a malformed
automated edit there can lock out all administrative access.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Optional

from auditforge.core.registry import ApplyOutcome, Primitive, ProbeResult, register
from auditforge.utils.safe_exec import resolve_binary, run, validate_token

_IDENT = r"^[A-Za-z][A-Za-z0-9_.]*$"
_ABSENT = {"__absent__": True}

AF_SYSCTL_DROPIN = "/etc/sysctl.d/90-auditforge.conf"
AF_SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-auditforge.conf"
AF_JOURNALD_DROPIN = "/etc/systemd/journald.conf.d/90-auditforge.conf"


def _atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.af_tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_lines(path: str) -> list:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def _guard_ssh_session(params: dict) -> None:
    if not params.get("guard") == "ssh_session":
        return
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        if os.environ.get("AUDITFORGE_ALLOW_SSH_RISK") != "1":
            raise RuntimeError(
                "refusing to apply: this session is an SSH connection and this control affects SSH "
                "authentication; re-run from a local console or set AUDITFORGE_ALLOW_SSH_RISK=1 to override"
            )


# ---------------------------------------------------------------------------
# sysctl (owns /etc/sysctl.d/90-auditforge.conf; never edits other files)
# ---------------------------------------------------------------------------


def _sysctl_runtime_get(key: str) -> Optional[str]:
    res = run([resolve_binary("sysctl"), "-n", key], timeout=10)
    if not res.ok:
        return None
    return res.stdout.strip()


def _sysctl_dropin_set(key: str, value: str) -> None:
    lines = [
        line
        for line in _read_lines(AF_SYSCTL_DROPIN)
        if not line.strip().startswith(f"{key} ") and not line.strip().startswith(f"{key}=")
    ]
    lines.append(f"{key} = {value}")
    _atomic_write(AF_SYSCTL_DROPIN, "\n".join(lines) + "\n")


def _sysctl_dropin_remove(key: str) -> None:
    lines = [
        line
        for line in _read_lines(AF_SYSCTL_DROPIN)
        if not line.strip().startswith(f"{key} ") and not line.strip().startswith(f"{key}=")
    ]
    _atomic_write(AF_SYSCTL_DROPIN, "\n".join(lines) + ("\n" if lines else ""))


@register
class SysctlPrimitive(Primitive):
    name = "linux_sysctl"

    def probe(self, params: dict) -> ProbeResult:
        key = validate_token(params["key"], r"^[a-z][a-z0-9_.]*$")
        value = _sysctl_runtime_get(key)
        if value is None:
            return ProbeResult(value=None, error=f"sysctl key '{key}' not readable on this kernel")
        try:
            typed: Any = int(value)
        except ValueError:
            typed = value
        return ProbeResult(value=typed, source="sysctl -n", raw={"key": key})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        key = validate_token(params["key"], r"^[a-z][a-z0-9_.]*$")
        target = params.get("value", expected_value)
        before = self.probe(params)
        _sysctl_dropin_set(key, str(target))
        res = run([resolve_binary("sysctl"), "-w", f"{key}={target}"], timeout=10)
        if not res.ok:
            raise RuntimeError(f"sysctl -w {key}={target} failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        key = validate_token(params["key"], r"^[a-z][a-z0-9_.]*$")
        _sysctl_dropin_remove(key)
        res = run([resolve_binary("sysctl"), "-w", f"{key}={change.previous_value}"], timeout=10)
        return res.ok


# ---------------------------------------------------------------------------
# sshd (owns /etc/ssh/sshd_config.d/00-auditforge.conf)
# ---------------------------------------------------------------------------


def _ensure_sshd_runtime_dir() -> None:
    # Both `sshd -T` (probe) and `sshd -t` (apply-path validation) refuse to
    # run at all -- printing "Missing privilege separation directory:
    # /run/sshd" on stdout with exit code 0 -- if this directory is absent,
    # which happens whenever sshd is currently stopped (the directory is
    # normally created by the service manager before sshd starts, not by
    # sshd itself). Ensuring it exists makes both probing and validating
    # config changes work regardless of whether the service is running.
    os.makedirs("/run/sshd", exist_ok=True)
    os.chmod("/run/sshd", 0o755)


def _sshd_effective_config() -> dict:
    _ensure_sshd_runtime_dir()
    exe = resolve_binary("sshd")
    res = run([exe, "-T", "-C", "user=root,host=localhost,addr=127.0.0.1,lport=22,laddr=127.0.0.1"], timeout=10)
    values = _parse_sshd_dump(res.stdout)
    if not values:
        res = run([exe, "-T"], timeout=10)
        values = _parse_sshd_dump(res.stdout)
    return values


def _parse_sshd_dump(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1]
    return values


def _sshd_dropin_set(option: str, value: str) -> None:
    lines = [line for line in _read_lines(AF_SSHD_DROPIN) if line.strip().split(None, 1)[:1] != [option]]
    lines.append(f"{option} {value}")
    _atomic_write(AF_SSHD_DROPIN, "\n".join(lines) + "\n")


def _sshd_dropin_remove(option: str) -> None:
    lines = [line for line in _read_lines(AF_SSHD_DROPIN) if line.strip().split(None, 1)[:1] != [option]]
    _atomic_write(AF_SSHD_DROPIN, "\n".join(lines) + ("\n" if lines else ""))


def _sshd_validate_and_reload() -> tuple:
    exe = resolve_binary("sshd")
    _ensure_sshd_runtime_dir()
    check = run([exe, "-t"], timeout=10)
    if not check.ok:
        return False, check.stderr.strip() or check.stdout.strip()
    for unit in ("sshd", "ssh"):
        res = run([resolve_binary("systemctl"), "reload", unit], timeout=15)
        if res.ok:
            return True, ""
    return False, "could not reload sshd/ssh service via systemctl"


@register
class SshdOptionPrimitive(Primitive):
    name = "linux_sshd_option"

    def probe(self, params: dict) -> ProbeResult:
        option = validate_token(params["option"], _IDENT).lower()
        config = _sshd_effective_config()
        if option not in config:
            return ProbeResult(value=None, error=f"sshd -T did not report option '{option}'")
        return ProbeResult(value=config[option], source="sshd -T", raw={"option": option})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        _guard_ssh_session(params)
        option = validate_token(params["option"], _IDENT)
        target = str(params.get("value", expected_value))
        before = self.probe(params)
        _sshd_dropin_set(option, target)
        ok, err = _sshd_validate_and_reload()
        if not ok:
            _sshd_dropin_remove(option)
            _sshd_validate_and_reload()
            raise RuntimeError(f"sshd config validation/reload failed, change reverted: {err}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        option = validate_token(params["option"], _IDENT)
        _sshd_dropin_remove(option)
        ok, _ = _sshd_validate_and_reload()
        return ok


# ---------------------------------------------------------------------------
# systemd units
# ---------------------------------------------------------------------------


@register
class SystemdUnitPrimitive(Primitive):
    name = "linux_systemd_unit"

    def probe(self, params: dict) -> ProbeResult:
        unit = validate_token(params["unit"], r"^[A-Za-z0-9_.\-@]+$")
        enabled = run([resolve_binary("systemctl"), "is-enabled", unit], timeout=10)
        active = run([resolve_binary("systemctl"), "is-active", unit], timeout=10)
        enabled_text = enabled.stdout.strip() or enabled.stderr.strip()
        if "not-found" in enabled_text or "No such file" in (enabled.stderr or ""):
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason=f"unit '{unit}' is not installed"
            )
        return ProbeResult(
            value=enabled_text,
            source="systemctl is-enabled",
            raw={"enabled": enabled_text, "active": active.stdout.strip()},
        )

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        _guard_ssh_session(params)
        unit = validate_token(params["unit"], r"^[A-Za-z0-9_.\-@]+$")
        target = params.get("value", expected_value)
        before = self.probe(params)
        verb = ["disable", "--now"] if str(target).lower() in ("disabled", "false") else ["enable", "--now"]
        res = run([resolve_binary("systemctl"), *verb, unit], timeout=30)
        if not res.ok:
            raise RuntimeError(f"systemctl {' '.join(verb)} {unit} failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        unit = validate_token(params["unit"], r"^[A-Za-z0-9_.\-@]+$")
        prev = str(change.previous_value or "").lower()
        verb = ["enable", "--now"] if "enabled" in prev else ["disable", "--now"]
        res = run([resolve_binary("systemctl"), *verb, unit], timeout=30)
        return res.ok


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


@register
class FilePermissionsPrimitive(Primitive):
    name = "linux_file_permissions"

    def probe(self, params: dict) -> ProbeResult:
        path = params["path"]
        if not os.path.exists(path):
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason=f"'{path}' does not exist")
        mode = oct(os.stat(path).st_mode & 0o777)[2:].zfill(3)
        return ProbeResult(value=mode, source="os.stat", raw={"path": path})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        path = params["path"]
        target = str(params.get("value", expected_value))
        before = self.probe(params)
        os.chmod(path, int(target, 8))
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        path = params["path"]
        if change.previous_value is None:
            return True
        try:
            os.chmod(path, int(str(change.previous_value), 8))
            return True
        except OSError:
            return False


@register
class StickyBitPrimitive(Primitive):
    """Audits/sets the sticky bit on shared-writable temp directories
    (e.g. /tmp) so users cannot delete/rename each other's files."""

    name = "linux_sticky_bit"

    def probe(self, params: dict) -> ProbeResult:
        path = params["path"]
        if not os.path.isdir(path):
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason=f"'{path}' does not exist")
        mode = os.stat(path).st_mode
        return ProbeResult(value=bool(mode & 0o1000), source="os.stat", raw={"path": path})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        path = params["path"]
        before = self.probe(params)
        current = os.stat(path).st_mode
        os.chmod(path, current | 0o1000)
        return ApplyOutcome(previous_value=before.value, new_value=True)

    def rollback(self, params: dict, change) -> bool:
        if change.previous_value:
            return True  # sticky bit was already set; nothing to undo
        path = params["path"]
        try:
            current = os.stat(path).st_mode
            os.chmod(path, current & ~0o1000)
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# /etc/login.defs (single-purpose file, safe to line-edit directly)
# ---------------------------------------------------------------------------

LOGIN_DEFS = "/etc/login.defs"


def _login_defs_get(key: str) -> Optional[str]:
    for line in _read_lines(LOGIN_DEFS):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = stripped.split(None, 1)
            if parts and parts[0] == key:
                return parts[1].strip() if len(parts) > 1 else ""
    return None


def _login_defs_set(key: str, value: str) -> None:
    lines = _read_lines(LOGIN_DEFS)
    out, found = [], False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.split(None, 1)[0] == key:
            out.append(f"{key}\t{value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}\t{value}")
    _atomic_write(LOGIN_DEFS, "\n".join(out) + "\n", mode=0o644)


@register
class LoginDefsPrimitive(Primitive):
    name = "linux_login_defs"

    def probe(self, params: dict) -> ProbeResult:
        key = validate_token(params["key"], r"^[A-Z][A-Z0-9_]*$")
        value = _login_defs_get(key)
        if value is None:
            return ProbeResult(value=params.get("default_if_absent"), raw={"exists": False})
        try:
            typed: Any = int(value)
        except ValueError:
            typed = value
        return ProbeResult(value=typed, source="/etc/login.defs", raw={"exists": True})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        key = validate_token(params["key"], r"^[A-Z][A-Z0-9_]*$")
        target = params.get("value", expected_value)
        existed = _login_defs_get(key) is not None
        before = self.probe(params)
        prev_recorded = before.value if existed else dict(_ABSENT)
        _login_defs_set(key, str(target))
        return ApplyOutcome(previous_value=prev_recorded, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        key = validate_token(params["key"], r"^[A-Z][A-Z0-9_]*$")
        prev = change.previous_value
        if isinstance(prev, dict) and prev.get("__absent__"):
            return True  # leaving the line in place with the new value is harmless; not worth removing
        _login_defs_set(key, str(prev))
        return True


# ---------------------------------------------------------------------------
# PAM pwquality / faillock (single-purpose conf files, safe to line-edit)
# ---------------------------------------------------------------------------


def _kv_conf_get(path: str, key: str) -> Optional[str]:
    for line in _read_lines(path):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, v = stripped.partition("=")
            if k.strip() == key:
                return v.strip()
    return None


def _kv_conf_set(path: str, key: str, value: str) -> None:
    lines = _read_lines(path)
    out, found = [], False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped and stripped.split("=", 1)[0].strip() == key:
            out.append(f"{key} = {value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key} = {value}")
    _atomic_write(path, "\n".join(out) + "\n", mode=0o644)


class _KvConfPrimitive(Primitive):
    conf_path = ""

    def probe(self, params: dict) -> ProbeResult:
        if not os.path.isfile(self.conf_path):
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason=f"{self.conf_path} not present on this system"
            )
        key = validate_token(params["key"], r"^[a-zA-Z][a-zA-Z0-9_]*$")
        value = _kv_conf_get(self.conf_path, key)
        if value is None:
            return ProbeResult(value=params.get("default_if_absent"), raw={"exists": False})
        try:
            typed: Any = int(value)
        except ValueError:
            typed = value
        return ProbeResult(value=typed, source=self.conf_path, raw={"exists": True})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        key = validate_token(params["key"], r"^[a-zA-Z][a-zA-Z0-9_]*$")
        target = params.get("value", expected_value)
        before = self.probe(params)
        _kv_conf_set(self.conf_path, key, str(target))
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        key = validate_token(params["key"], r"^[a-zA-Z][a-zA-Z0-9_]*$")
        prev = change.previous_value
        if prev is None:
            return True
        _kv_conf_set(self.conf_path, key, str(prev))
        return True


@register
class PwqualityPrimitive(_KvConfPrimitive):
    name = "linux_pwquality"
    conf_path = "/etc/security/pwquality.conf"


@register
class FaillockPrimitive(_KvConfPrimitive):
    name = "linux_faillock"
    conf_path = "/etc/security/faillock.conf"


# ---------------------------------------------------------------------------
# sudoers -- audit only, never auto-edited (lockout risk)
# ---------------------------------------------------------------------------


@register
class SudoersNopasswdScanPrimitive(Primitive):
    name = "linux_sudoers_nopasswd_scan"

    def probe(self, params: dict) -> ProbeResult:
        hits = []
        for base in ("/etc/sudoers", "/etc/sudoers.d"):
            paths = [base] if os.path.isfile(base) else (
                [os.path.join(base, f) for f in os.listdir(base)] if os.path.isdir(base) else []
            )
            for path in paths:
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        for lineno, line in enumerate(fh, 1):
                            if "NOPASSWD" in line and not line.strip().startswith("#"):
                                hits.append(f"{path}:{lineno}")
                except OSError:
                    continue
        return ProbeResult(
            value=len(hits),
            source="sudoers scan",
            raw={"lines": hits},
            manual_review=True,
            manual_review_reason=(
                f"{len(hits)} NOPASSWD sudoers entr(y/ies) found: {', '.join(hits) or '(none)'}. "
                "May be intentional (automation accounts) -- review, do not assume this is wrong."
            ),
        )


# ---------------------------------------------------------------------------
# Firewalls -- detect, never flush; enable only the tool already present
# ---------------------------------------------------------------------------


@register
class FirewallManagerDetectPrimitive(Primitive):
    """Audit-only: which firewall manager(s) are active. Never remediated
    automatically -- see linux_ufw_status / linux_firewalld_status for the
    (deliberately narrow, non-destructive) enable-only remediations."""

    name = "linux_firewall_manager_detect"

    def probe(self, params: dict) -> ProbeResult:
        active = []
        for unit in ("ufw", "firewalld"):
            res = run([resolve_binary("systemctl"), "is-active", unit], timeout=10)
            if res.ok and res.stdout.strip() == "active":
                active.append(unit)
        nft = run([resolve_binary("nft"), "list", "ruleset"], timeout=10)
        has_nft_rules = nft.ok and len(nft.stdout.strip().splitlines()) > 0
        if has_nft_rules and "ufw" not in active:
            active.append("nftables (rules present, no ufw/firewalld unit)")
        return ProbeResult(
            value=bool(active), source="systemctl/nft", raw={"active_managers": active},
            manual_review=not active,
            manual_review_reason="no firewall manager detected as active" if not active else "",
        )


@register
class UfwStatusPrimitive(Primitive):
    name = "linux_ufw_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run([resolve_binary("ufw"), "status"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="ufw is not installed")
        active = res.stdout.strip().lower().startswith("status: active")
        return ProbeResult(value=active, source="ufw status", raw={"raw": res.stdout.strip()})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        before = self.probe(params)
        res = run([resolve_binary("ufw"), "--force", "enable"], timeout=20)
        if not res.ok:
            raise RuntimeError(f"ufw enable failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=True)

    def rollback(self, params: dict, change) -> bool:
        if change.previous_value:
            return True
        res = run([resolve_binary("ufw"), "disable"], timeout=20)
        return res.ok


@register
class FirewalldStatusPrimitive(Primitive):
    name = "linux_firewalld_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run([resolve_binary("systemctl"), "is-active", "firewalld"], timeout=10)
        text = res.stdout.strip() or res.stderr.strip()
        if "not-found" in text or "could not be found" in text.lower():
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="firewalld is not installed")
        return ProbeResult(value=(text == "active"), source="systemctl is-active firewalld")

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        before = self.probe(params)
        res = run([resolve_binary("systemctl"), "enable", "--now", "firewalld"], timeout=20)
        if not res.ok:
            raise RuntimeError(f"failed to enable firewalld: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=True)

    def rollback(self, params: dict, change) -> bool:
        if change.previous_value:
            return True
        res = run([resolve_binary("systemctl"), "disable", "--now", "firewalld"], timeout=20)
        return res.ok


# ---------------------------------------------------------------------------
# Filesystem-wide audit-only scans
# ---------------------------------------------------------------------------


@register
class SuidBinaryCountPrimitive(Primitive):
    """Audit-only: SUID/SGID binary inventory for manual review. Baseline
    counts vary a lot by distro/installed packages, so this is
    MANUAL_REVIEW, not a pass/fail against a fixed number."""

    name = "linux_suid_binary_count"

    def probe(self, params: dict) -> ProbeResult:
        find = resolve_binary("find") if _has_find() else None
        if not find:
            return ProbeResult(value=None, error="'find' binary not available")
        res = run([find, "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=60)
        paths = [p for p in res.stdout.splitlines() if p.strip()]
        return ProbeResult(
            value=len(paths),
            source="find / -xdev -perm -4000",
            raw={"paths": paths[:200]},
            manual_review=True,
            manual_review_reason=f"{len(paths)} SUID binaries found on the root filesystem; review for anything unexpected.",
        )


def _has_find() -> bool:
    try:
        resolve_binary("find")
        return True
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# journald persistent storage (owns journald.conf.d/90-auditforge.conf)
# ---------------------------------------------------------------------------


@register
class JournaldPersistentPrimitive(Primitive):
    name = "linux_journald_persistent"

    def probe(self, params: dict) -> ProbeResult:
        value = _kv_conf_get("/etc/systemd/journald.conf", "Storage")
        dropin_value = None
        if os.path.isfile(AF_JOURNALD_DROPIN):
            dropin_value = _kv_conf_get(AF_JOURNALD_DROPIN, "Storage")
        effective = dropin_value or value or "auto"
        persistent = effective.lower() in ("persistent",) or os.path.isdir("/var/log/journal")
        return ProbeResult(value=persistent, source="journald.conf(.d) / /var/log/journal", raw={"effective": effective})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        before = self.probe(params)
        _atomic_write(AF_JOURNALD_DROPIN, "[Journal]\nStorage=persistent\n")
        res = run([resolve_binary("systemctl"), "restart", "systemd-journald"], timeout=20)
        if not res.ok:
            raise RuntimeError(f"failed to restart systemd-journald: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=True)

    def rollback(self, params: dict, change) -> bool:
        if os.path.isfile(AF_JOURNALD_DROPIN):
            os.remove(AF_JOURNALD_DROPIN)
        res = run([resolve_binary("systemctl"), "restart", "systemd-journald"], timeout=20)
        return res.ok


# ---------------------------------------------------------------------------
# Pending package updates (audit only; distro-family aware)
# ---------------------------------------------------------------------------


@register
class SecureBootStatusPrimitive(Primitive):
    """Audit-only: UEFI Secure Boot state via mokutil, where available."""

    name = "linux_secure_boot_status"

    def probe(self, params: dict) -> ProbeResult:
        if not shutil.which("mokutil"):
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason="mokutil not installed (or not a UEFI system)"
            )
        res = run(["mokutil", "--sb-state"], timeout=10)
        if not res.ok:
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="not a UEFI Secure Boot capable system")
        enabled = "enabled" in res.stdout.lower()
        return ProbeResult(value=enabled, source="mokutil --sb-state", raw={"raw": res.stdout.strip()})


@register
class PendingUpdatesPrimitive(Primitive):
    name = "linux_pending_updates"

    def probe(self, params: dict) -> ProbeResult:
        if shutil.which("apt-get"):
            res = run(["apt-get", "-s", "upgrade"], timeout=60)
            if not res.ok:
                return ProbeResult(value=None, error=res.stderr.strip() or "apt-get -s upgrade failed")
            count = sum(1 for line in res.stdout.splitlines() if line.startswith("Inst "))
            return ProbeResult(value=count, source="apt-get -s upgrade")
        for mgr in ("dnf", "yum"):
            if shutil.which(mgr):
                res = run([mgr, "-q", "check-update"], timeout=60)
                # check-update exit codes: 0 = no updates, 100 = updates available, other = error
                if res.returncode not in (0, 100):
                    return ProbeResult(value=None, error=res.stderr.strip() or f"{mgr} check-update failed")
                count = sum(
                    1
                    for line in res.stdout.splitlines()
                    if line.strip() and not line.startswith(("Last metadata", "Obsoleting"))
                )
                return ProbeResult(value=count if res.returncode == 100 else 0, source=f"{mgr} check-update")
        return ProbeResult(value=None, error="no supported package manager (apt/dnf/yum) found")
