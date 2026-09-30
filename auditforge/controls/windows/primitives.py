"""Windows probe/apply primitives.

Every class here is registered into auditforge.core.registry and referenced
by name from controls/windows/*.yml. See docs/ARCHITECTURE.md for the
rationale (control files declare *which* primitive + params, never code).

Registry reads/writes use the stdlib `winreg` module directly (no subprocess,
no injection surface at all). Everything else that needs live Windows state
(services, firewall, Defender, SMB, BitLocker, TPM, Windows Update...) goes
through PowerShell, always via safe_exec.run_powershell (stdin, never
-Command string interpolation) and always with property/parameter names
validated against an identifier allowlist before they're placed in a script,
even though those names come from our own trusted control YAML.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any, Optional

from auditforge.core.registry import ApplyOutcome, Primitive, ProbeResult, register
from auditforge.utils.safe_exec import resolve_binary, run, run_powershell, validate_token

try:
    import winreg
except ImportError:  # pragma: no cover - only real on non-Windows dev/CI hosts
    winreg = None

_IDENT = r"^[A-Za-z][A-Za-z0-9_]*$"

_HIVES = {
    "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", None),
    "HKCU": getattr(winreg, "HKEY_CURRENT_USER", None),
}

_ABSENT = {"__absent__": True}

# Several nominally "enum" Get-MpPreference properties (EnableControlledFolderAccess,
# EnableNetworkProtection, ...) are typed as a plain System.Byte, not a real .NET enum --
# unlike Get-Service/Get-NetFirewallProfile, a .ToString() on the property does not
# recover the string name, so we map the known integer values back to the names
# Set-MpPreference (and the control YAML's expected_value) use.
_DEFENDER_ENABLE_ENUM = {0: "Disabled", 1: "Enabled", 2: "AuditMode"}


def _require_winreg():
    if winreg is None:
        raise RuntimeError("winreg module unavailable; this primitive only runs on Windows")


def _hive(name: str):
    _require_winreg()
    try:
        return _HIVES[name]
    except KeyError as exc:
        raise ValueError(f"unsupported registry hive '{name}', expected one of {list(_HIVES)}") from exc


def _guard_connectivity(params: dict) -> None:
    guard = params.get("guard")
    if guard == "current_session_rdp" and os.environ.get("SESSIONNAME", "").upper().startswith("RDP-"):
        raise RuntimeError(
            "refusing to apply: the current session is an RDP session and this control "
            "affects RDP; re-run from a local/console session or pass an explicit override"
        )


def _read_reg(hive: str, path: str, name: str):
    _require_winreg()
    try:
        with winreg.OpenKey(_hive(hive), path) as key:
            value, _vtype = winreg.QueryValueEx(key, name)
            return value, True
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, False


def _write_reg(hive: str, path: str, name: str, value: Any, value_type: int) -> None:
    _require_winreg()
    with winreg.CreateKeyEx(_hive(hive), path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, value_type, value)


def _delete_reg(hive: str, path: str, name: str) -> None:
    _require_winreg()
    try:
        with winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def _policy_source(path: str) -> Optional[str]:
    return "Registry Policy key (SOFTWARE\\Policies)" if "\\policies\\" in path.lower() else None


def _ps_json(expression: str, timeout: int = 25):
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"try {{ {expression} | ConvertTo-Json -Compress -Depth 5 }} "
        "catch { Write-Output '__AF_PS_ERROR__'; Write-Error $_.Exception.Message }"
    )
    res = run_powershell(script, timeout=timeout)
    text = (res.stdout or "").strip()
    if not res.ok or not text or text == "__AF_PS_ERROR__":
        return None, (res.stderr or "").strip() or "command failed"
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        return text, None


def _ps_literal(value: Any, value_type: str = "bool") -> str:
    if value_type == "bool":
        return "$true" if value else "$false"
    if value_type == "int":
        return str(int(value))
    if value_type == "string_enum":
        token = validate_token(str(value), r"^[A-Za-z][A-Za-z0-9_]*$")
        return f"'{token}'"
    raise ValueError(f"unsupported value_type '{value_type}'")


# ---------------------------------------------------------------------------
# Registry primitives
# ---------------------------------------------------------------------------


@register
class RegistryDwordPrimitive(Primitive):
    name = "win_registry_dword"

    def probe(self, params: dict) -> ProbeResult:
        hive, path, value_name = params["hive"], params["path"], params["name"]
        value, exists = _read_reg(hive, path, value_name)
        raw = {"exists": exists}
        src = _policy_source(path)
        if src:
            raw["policy_source"] = src
        if not exists:
            value = params.get("default_if_absent", 0)
            raw["used_default"] = True
        return ProbeResult(value=value, raw=raw, source=f"registry:{hive}\\{path}\\{value_name}")

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        _guard_connectivity(params)
        hive, path, value_name = params["hive"], params["path"], params["name"]
        previous, existed = _read_reg(hive, path, value_name)
        prev_recorded = previous if existed else dict(_ABSENT)
        target = int(params.get("value", expected_value))
        _write_reg(hive, path, value_name, target, winreg.REG_DWORD)
        return ApplyOutcome(previous_value=prev_recorded, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        hive, path, value_name = params["hive"], params["path"], params["name"]
        prev = change.previous_value
        if isinstance(prev, dict) and prev.get("__absent__"):
            _delete_reg(hive, path, value_name)
            _, exists = _read_reg(hive, path, value_name)
            return not exists
        _write_reg(hive, path, value_name, int(prev), winreg.REG_DWORD)
        new_val, exists = _read_reg(hive, path, value_name)
        return exists and new_val == int(prev)


@register
class RegistryStringPrimitive(Primitive):
    name = "win_registry_string"

    def probe(self, params: dict) -> ProbeResult:
        hive, path, value_name = params["hive"], params["path"], params["name"]
        value, exists = _read_reg(hive, path, value_name)
        raw = {"exists": exists}
        src = _policy_source(path)
        if src:
            raw["policy_source"] = src
        if not exists:
            value = params.get("default_if_absent", "")
            raw["used_default"] = True
        return ProbeResult(value=value, raw=raw, source=f"registry:{hive}\\{path}\\{value_name}")

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        _guard_connectivity(params)
        hive, path, value_name = params["hive"], params["path"], params["name"]
        previous, existed = _read_reg(hive, path, value_name)
        prev_recorded = previous if existed else dict(_ABSENT)
        target = str(params.get("value", expected_value))
        _write_reg(hive, path, value_name, target, winreg.REG_SZ)
        return ApplyOutcome(previous_value=prev_recorded, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        hive, path, value_name = params["hive"], params["path"], params["name"]
        prev = change.previous_value
        if isinstance(prev, dict) and prev.get("__absent__"):
            _delete_reg(hive, path, value_name)
            _, exists = _read_reg(hive, path, value_name)
            return not exists
        _write_reg(hive, path, value_name, str(prev), winreg.REG_SZ)
        new_val, exists = _read_reg(hive, path, value_name)
        return exists and new_val == str(prev)


# ---------------------------------------------------------------------------
# Local security policy (secedit) -- export full policy, patch one field,
# reapply the FULL policy so unrelated settings are never reset to defaults.
# ---------------------------------------------------------------------------

_SECEDIT_KEYS = {
    "MinimumPasswordAge",
    "MaximumPasswordAge",
    "MinimumPasswordLength",
    "PasswordComplexity",
    "PasswordHistorySize",
    "ClearTextPassword",
    "LockoutBadCount",
    "ResetLockoutCount",
    "LockoutDuration",
    "ForceLogoffWhenHourExpire",
    "NewAdministratorName",
    "NewGuestName",
    "EnableGuestAccount",
    "LSAAnonymousNameLookup",
}


def _secedit_export() -> str:
    exe = resolve_binary("secedit.exe")
    tmpdir = tempfile.mkdtemp(prefix="af_secedit_")
    try:
        cfg_path = os.path.join(tmpdir, "export.inf")
        res = run([exe, "/export", "/cfg", cfg_path, "/areas", "SECURITYPOLICY"], timeout=40)
        if not res.ok or not os.path.isfile(cfg_path):
            raise RuntimeError(f"secedit /export failed: {res.stderr.strip() or res.stdout.strip()}")
        with open(cfg_path, encoding="utf-16") as fh:
            return fh.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _secedit_parse(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("["):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def _secedit_lookup(key: str, export_text: str) -> tuple:
    """Parse already-exported secedit text and return (value, raw_str)
    for `key`, or (None, None) if the key is not present in the export."""
    values = _secedit_parse(export_text)
    if key not in values:
        return None, None
    raw = values[key]
    try:
        value: Any = int(raw)
    except ValueError:
        value = raw
    return value, raw


def _secedit_apply(key: str, new_value: str, export_text: Optional[str] = None) -> None:
    validate_token(key, _IDENT)
    validate_token(str(new_value), r"^[A-Za-z0-9,]+$")
    text = export_text if export_text is not None else _secedit_export()
    lines = text.splitlines()
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("["):
            k, _, _v = stripped.partition("=")
            if k.strip() == key:
                lines[i] = f"{key} = {new_value}"
                found = True
                break
    if not found:
        raise RuntimeError(f"secedit export did not contain key '{key}'; cannot safely patch policy")

    tmpdir = tempfile.mkdtemp(prefix="af_secedit_")
    try:
        cfg_path = os.path.join(tmpdir, "apply.inf")
        db_path = os.path.join(tmpdir, "scratch.sdb")
        with open(cfg_path, "w", encoding="utf-16") as fh:
            fh.write("\n".join(lines))
        exe = resolve_binary("secedit.exe")
        res = run(
            [exe, "/configure", "/db", db_path, "/cfg", cfg_path, "/areas", "SECURITYPOLICY"],
            timeout=60,
        )
        if not res.ok:
            raise RuntimeError(f"secedit /configure failed: {res.stderr.strip() or res.stdout.strip()}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@register
class SeceditPolicyPrimitive(Primitive):
    name = "win_secedit_policy"

    def probe(self, params: dict) -> ProbeResult:
        key = validate_token(params["key"], _IDENT)
        try:
            export_text = _secedit_export()
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(value=None, error=str(exc))
        value, raw = _secedit_lookup(key, export_text)
        if raw is None:
            return ProbeResult(value=None, error=f"key '{key}' not present in exported security policy")
        return ProbeResult(value=value, source="secedit /export", raw={"key": key, "raw": raw})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        key = params["key"]
        if key not in _SECEDIT_KEYS:
            raise ValueError(f"'{key}' is not in the secedit allowlist")
        key = validate_token(key, _IDENT)
        target = params.get("value", expected_value)
        # Export the current policy once and reuse it both to determine the
        # previous value and (inside _secedit_apply) to build the patched
        # .inf -- secedit /export spawns a process and does temp-file I/O,
        # so this halves that cost versus exporting twice for one apply().
        export_text = _secedit_export()
        previous_value, _raw = _secedit_lookup(key, export_text)
        _secedit_apply(key, str(target), export_text=export_text)
        return ApplyOutcome(previous_value=previous_value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        try:
            _secedit_apply(params["key"], str(change.previous_value))
        except Exception:  # noqa: BLE001
            return False
        after = self.probe(params)
        return str(after.value) == str(change.previous_value)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


@register
class ServiceStatePrimitive(Primitive):
    name = "win_service_state"

    def probe(self, params: dict) -> ProbeResult:
        svc = validate_token(params["service_name"], r"^[A-Za-z0-9_\-]+$")
        # Get-Service's Status/StartType are enums that ConvertTo-Json
        # otherwise serializes as raw integers -- force .ToString() so the
        # comparison against a human-readable expected_value (e.g.
        # "Disabled") actually works.
        data, err = _ps_json(
            f"Get-Service -Name '{svc}' | "
            "Select-Object @{N='Status';E={$_.Status.ToString()}},@{N='StartType';E={$_.StartType.ToString()}}"
        )
        if err or not data:
            return ProbeResult(value=None, error=err or "service not found")
        return ProbeResult(
            value=str(data.get("StartType")),
            source="Get-Service",
            raw={"status": str(data.get("Status")), "start_type": str(data.get("StartType"))},
        )

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        _guard_connectivity(params)
        svc = validate_token(params["service_name"], r"^[A-Za-z0-9_\-]+$")
        target = validate_token(str(params.get("value", expected_value)), _IDENT)
        before = self.probe(params)
        script = f"Set-Service -Name '{svc}' -StartupType {target}"
        if target.lower() == "disabled":
            script += f"; Stop-Service -Name '{svc}' -Force -ErrorAction SilentlyContinue"
        res = run_powershell(script, timeout=30)
        if not res.ok:
            raise RuntimeError(f"Set-Service '{svc}' failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target, notes=script)

    def rollback(self, params: dict, change) -> bool:
        svc = validate_token(params["service_name"], r"^[A-Za-z0-9_\-]+$")
        prev = validate_token(str(change.previous_value), _IDENT)
        script = f"Set-Service -Name '{svc}' -StartupType {prev}"
        if prev.lower() != "disabled":
            script += f"; Start-Service -Name '{svc}' -ErrorAction SilentlyContinue"
        res = run_powershell(script, timeout=30)
        return res.ok


# ---------------------------------------------------------------------------
# Firewall profiles
# ---------------------------------------------------------------------------


@register
class FirewallProfilePrimitive(Primitive):
    name = "win_firewall_profile"

    def probe(self, params: dict) -> ProbeResult:
        profile = validate_token(params["profile"], _IDENT)
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        if value_type == "string_enum":
            # DefaultInboundAction/DefaultOutboundAction are real .NET enums,
            # but -ExpandProperty | ConvertTo-Json serializes the underlying
            # int, not the name -- force .ToString() so the result compares
            # correctly against string expected_value (e.g. "Block").
            expr = f"(Get-NetFirewallProfile -Profile {profile}).{prop}.ToString()"
        else:
            expr = f"Get-NetFirewallProfile -Profile {profile} | Select-Object -ExpandProperty {prop}"
        data, err = _ps_json(expr)
        if err:
            return ProbeResult(value=None, error=err)
        return ProbeResult(value=data, source="Get-NetFirewallProfile", raw={"profile": profile, "property": prop})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        profile = validate_token(params["profile"], _IDENT)
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        target = params.get("value", expected_value)
        before = self.probe(params)
        literal = _ps_literal(target, value_type)
        res = run_powershell(f"Set-NetFirewallProfile -Profile {profile} -{prop} {literal}", timeout=20)
        if not res.ok:
            raise RuntimeError(f"Set-NetFirewallProfile failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        profile = validate_token(params["profile"], _IDENT)
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        literal = _ps_literal(change.previous_value, value_type)
        res = run_powershell(f"Set-NetFirewallProfile -Profile {profile} -{prop} {literal}", timeout=20)
        return res.ok


# ---------------------------------------------------------------------------
# Windows optional features (e.g. SMB1Protocol, PowerShell v2 engine)
# ---------------------------------------------------------------------------


@register
class OptionalFeaturePrimitive(Primitive):
    name = "win_optional_feature"

    def probe(self, params: dict) -> ProbeResult:
        feature = validate_token(params["feature_name"], r"^[A-Za-z0-9_]+$")
        res = run_powershell(f"(Get-WindowsOptionalFeature -Online -FeatureName '{feature}').State", timeout=30)
        text = (res.stdout or "").strip()
        if not res.ok and res.stderr.strip():
            return ProbeResult(value=None, error=res.stderr.strip())
        if not text:
            # Cmdlet succeeded but returned nothing: this optional feature
            # does not exist on this SKU/edition/language variant at all.
            return ProbeResult(
                value=None,
                not_applicable=True,
                not_applicable_reason=f"optional feature '{feature}' does not exist on this Windows SKU/edition",
            )
        return ProbeResult(value=text, source="Get-WindowsOptionalFeature", raw={"feature": feature})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        feature = validate_token(params["feature_name"], r"^[A-Za-z0-9_]+$")
        target_state = params.get("value", expected_value)
        before = self.probe(params)
        verb = "Disable" if str(target_state).lower() == "disabled" else "Enable"
        res = run_powershell(
            f"{verb}-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart | Out-Null", timeout=180
        )
        if not res.ok:
            raise RuntimeError(f"{verb}-WindowsOptionalFeature failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(
            previous_value=before.value, new_value=target_state, notes="reboot required to fully complete"
        )

    def rollback(self, params: dict, change) -> bool:
        feature = validate_token(params["feature_name"], r"^[A-Za-z0-9_]+$")
        prev = change.previous_value
        verb = "Disable" if str(prev).lower() == "disabled" else "Enable"
        res = run_powershell(
            f"{verb}-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart | Out-Null", timeout=180
        )
        return res.ok


# ---------------------------------------------------------------------------
# SMB server configuration
# ---------------------------------------------------------------------------


@register
class SmbServerConfigPrimitive(Primitive):
    name = "win_smb_server_config"

    def probe(self, params: dict) -> ProbeResult:
        prop = validate_token(params["property"], _IDENT)
        data, err = _ps_json(f"Get-SmbServerConfiguration | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(value=None, error=err)
        return ProbeResult(value=data, source="Get-SmbServerConfiguration", raw={"property": prop})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        target = params.get("value", expected_value)
        before = self.probe(params)
        literal = _ps_literal(target, value_type)
        res = run_powershell(f"Set-SmbServerConfiguration -{prop} {literal} -Force", timeout=30)
        if not res.ok:
            raise RuntimeError(f"Set-SmbServerConfiguration failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        literal = _ps_literal(change.previous_value, value_type)
        res = run_powershell(f"Set-SmbServerConfiguration -{prop} {literal} -Force", timeout=30)
        return res.ok


@register
class SmbClientConfigPrimitive(Primitive):
    name = "win_smb_client_config"

    def probe(self, params: dict) -> ProbeResult:
        prop = validate_token(params["property"], _IDENT)
        data, err = _ps_json(f"Get-SmbClientConfiguration | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(value=None, error=err)
        return ProbeResult(value=data, source="Get-SmbClientConfiguration", raw={"property": prop})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        target = params.get("value", expected_value)
        before = self.probe(params)
        literal = _ps_literal(target, value_type)
        res = run_powershell(f"Set-SmbClientConfiguration -{prop} {literal} -Force", timeout=30)
        if not res.ok:
            raise RuntimeError(f"Set-SmbClientConfiguration failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        prop = validate_token(params["property"], _IDENT)
        value_type = params.get("value_type", "bool")
        literal = _ps_literal(change.previous_value, value_type)
        res = run_powershell(f"Set-SmbClientConfiguration -{prop} {literal} -Force", timeout=30)
        return res.ok


# ---------------------------------------------------------------------------
# Microsoft Defender
# ---------------------------------------------------------------------------


@register
class DefenderPreferencePrimitive(Primitive):
    """A Defender setting that is both readable and settable via
    Get-MpPreference / Set-MpPreference (real-time protection, cloud
    protection level, PUA protection, ASR/network protection, ...)."""

    name = "win_defender_preference"

    def probe(self, params: dict) -> ProbeResult:
        prop = validate_token(params["pref_property"], _IDENT)
        invert = bool(params.get("invert", False))
        value_type = params.get("value_type", "bool")
        data, err = _ps_json(f"Get-MpPreference | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason="Microsoft Defender not present/queryable"
            )
        if value_type == "string_enum" and isinstance(data, int) and not isinstance(data, bool):
            data = _DEFENDER_ENABLE_ENUM.get(data, data)
        value = (not data) if (invert and isinstance(data, bool)) else data
        return ProbeResult(value=value, source="Get-MpPreference", raw={"property": prop})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        prop = validate_token(params["set_param"], _IDENT)
        value_type = params.get("value_type", "bool")
        invert = bool(params.get("invert", False))
        target_user_facing = params.get("value", expected_value)
        raw_target = (not target_user_facing) if (invert and isinstance(target_user_facing, bool)) else target_user_facing
        before = self.probe(params)
        literal = _ps_literal(raw_target, value_type)
        res = run_powershell(f"Set-MpPreference -{prop} {literal}", timeout=30)
        if not res.ok:
            raise RuntimeError(f"Set-MpPreference -{prop} failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target_user_facing)

    def rollback(self, params: dict, change) -> bool:
        prop = validate_token(params["set_param"], _IDENT)
        value_type = params.get("value_type", "bool")
        invert = bool(params.get("invert", False))
        prev_user_facing = change.previous_value
        raw_prev = (not prev_user_facing) if (invert and isinstance(prev_user_facing, bool)) else prev_user_facing
        literal = _ps_literal(raw_prev, value_type)
        res = run_powershell(f"Set-MpPreference -{prop} {literal}", timeout=30)
        return res.ok


@register
class DefenderStatusPrimitive(Primitive):
    """Audit-only Defender status flags with no safe direct setter
    (IsTamperProtected, AntivirusEnabled, NISEnabled, ...)."""

    name = "win_defender_status"

    def probe(self, params: dict) -> ProbeResult:
        prop = validate_token(params["property"], _IDENT)
        data, err = _ps_json(f"Get-MpComputerStatus | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason="Microsoft Defender not present/queryable"
            )
        return ProbeResult(value=data, source="Get-MpComputerStatus", raw={"property": prop})


# ---------------------------------------------------------------------------
# Local accounts
# ---------------------------------------------------------------------------


@register
class LocalUserStatusPrimitive(Primitive):
    name = "win_local_user_status"

    def probe(self, params: dict) -> ProbeResult:
        user = validate_token(params["username"], r"^[A-Za-z0-9_\-\.\$]+$")
        prop = validate_token(params["property"], _IDENT)
        data, err = _ps_json(f"Get-LocalUser -Name '{user}' -ErrorAction Stop | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason=f"local account '{user}' not present"
            )
        return ProbeResult(value=data, source="Get-LocalUser", raw={"user": user, "property": prop})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        user = validate_token(params["username"], r"^[A-Za-z0-9_\-\.\$]+$")
        prop = params["property"]
        target = params.get("value", expected_value)
        before = self.probe(params)
        if prop == "Enabled":
            verb = "Enable" if target else "Disable"
            res = run_powershell(f"{verb}-LocalUser -Name '{user}'", timeout=20)
        else:
            raise NotImplementedError(f"win_local_user_status remediation only supports 'Enabled', not '{prop}'")
        if not res.ok:
            raise RuntimeError(f"local user update failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        user = validate_token(params["username"], r"^[A-Za-z0-9_\-\.\$]+$")
        verb = "Enable" if change.previous_value else "Disable"
        res = run_powershell(f"{verb}-LocalUser -Name '{user}'", timeout=20)
        return res.ok


@register
class LocalAdminsCountPrimitive(Primitive):
    """Audit-only: who is in the local Administrators group. Automating
    membership removal is deliberately not supported -- section 13's
    'never blindly delete administrator accounts' -- this is a
    MANUAL_REVIEW-style finding for a human to act on."""

    name = "win_local_admins_count"

    def probe(self, params: dict) -> ProbeResult:
        data, err = _ps_json("Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name")
        if err:
            return ProbeResult(value=None, error=err)
        members = data if isinstance(data, list) else ([data] if data else [])
        return ProbeResult(
            value=len(members),
            source="Get-LocalGroupMember",
            raw={"members": members},
            manual_review=True,
            manual_review_reason=(
                f"{len(members)} account(s) in local Administrators group: {', '.join(members) or '(none)'}. "
                "Review for staleness/necessity -- membership size alone is not a reliable pass/fail signal."
            ),
        )


# ---------------------------------------------------------------------------
# NetBIOS
# ---------------------------------------------------------------------------


@register
class NetbiosStatusPrimitive(Primitive):
    name = "win_netbios_status"

    def probe(self, params: dict) -> ProbeResult:
        data, err = _ps_json(
            "Get-CimInstance Win32_NetworkAdapterConfiguration | "
            "Where-Object { $_.TcpipNetbiosOptions -ne $null } | "
            "Select-Object -ExpandProperty TcpipNetbiosOptions"
        )
        if err:
            return ProbeResult(value=None, error=err)
        values = data if isinstance(data, list) else ([data] if data is not None else [])
        disabled_everywhere = all(v == 2 for v in values) if values else True
        return ProbeResult(value=disabled_everywhere, source="Win32_NetworkAdapterConfiguration", raw={"per_adapter": values})

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        before = self.probe(params)
        script = (
            "Get-CimInstance Win32_NetworkAdapterConfiguration | "
            "Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null"
        )
        res = run_powershell(script, timeout=30)
        if not res.ok:
            raise RuntimeError(f"SetTcpipNetbios failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.raw.get("per_adapter"), new_value=True)

    def rollback(self, params: dict, change) -> bool:
        # Best-effort: restore per-adapter values recorded before the change.
        prev_values = change.previous_value or []
        if not prev_values or all(v == 2 for v in prev_values):
            return True  # nothing to restore, or it was already disabled everywhere
        target = prev_values[0]
        res = run_powershell(
            "Get-CimInstance Win32_NetworkAdapterConfiguration | "
            f"Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{{TcpipNetbiosOptions={int(target)}}} | Out-Null",
            timeout=30,
        )
        return res.ok


# ---------------------------------------------------------------------------
# Audit-only status primitives: encryption, boot integrity, updates
# ---------------------------------------------------------------------------


@register
class BitlockerStatusPrimitive(Primitive):
    """Audit-only by design (section 6: never auto-enable encryption
    without protecting recovery keys first)."""

    name = "win_bitlocker_status"

    def probe(self, params: dict) -> ProbeResult:
        mount = validate_token(params.get("mount_point", "C:"), r"^[A-Za-z]:$")
        data, err = _ps_json(
            f"Get-BitLockerVolume -MountPoint '{mount}' | "
            "Select-Object @{N='ProtectionStatus';E={$_.ProtectionStatus.ToString()}},"
            "@{N='VolumeStatus';E={$_.VolumeStatus.ToString()}},EncryptionMethod"
        )
        if err:
            return ProbeResult(
                value=None, not_applicable=True, not_applicable_reason="BitLocker not available on this edition/host"
            )
        protection = str(data.get("ProtectionStatus", "Unknown"))
        return ProbeResult(value=protection, source="Get-BitLockerVolume", raw=data)


@register
class SecureBootStatusPrimitive(Primitive):
    name = "win_secure_boot_status"

    def probe(self, params: dict) -> ProbeResult:
        res = run_powershell("try { Confirm-SecureBootUEFI } catch { '__AF_NA__' }", timeout=15)
        text = (res.stdout or "").strip()
        if text == "__AF_NA__" or not res.ok:
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="not a UEFI system")
        return ProbeResult(value=text.lower() == "true", source="Confirm-SecureBootUEFI")


@register
class TpmStatusPrimitive(Primitive):
    name = "win_tpm_status"

    def probe(self, params: dict) -> ProbeResult:
        prop = validate_token(params.get("property", "TpmReady"), _IDENT)
        data, err = _ps_json(f"Get-Tpm | Select-Object -ExpandProperty {prop}")
        if err:
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="no TPM detected/queryable")
        return ProbeResult(value=data, source="Get-Tpm", raw={"property": prop})


@register
class PendingRebootPrimitive(Primitive):
    name = "win_pending_reboot"

    def probe(self, params: dict) -> ProbeResult:
        script = (
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending',"
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'"
            ")\n"
            "($paths | Where-Object { Test-Path $_ }).Count -gt 0"
        )
        res = run_powershell(script, timeout=15)
        text = (res.stdout or "").strip()
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip())
        return ProbeResult(value=text.lower() == "true", source="registry reboot-pending flags")


@register
class PendingUpdatesPrimitive(Primitive):
    """Audit-only: count of not-installed software updates via the Windows
    Update Agent COM API. Can be slow/blocked on WSUS-managed machines --
    treated as MANUAL_REVIEW territory (ERROR) rather than a false PASS."""

    name = "win_pending_updates"

    def probe(self, params: dict) -> ProbeResult:
        script = (
            "try {\n"
            "  $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()\n"
            "  $r = $s.Search(\"IsInstalled=0 and Type='Software'\")\n"
            "  $r.Updates.Count\n"
            "} catch { Write-Output '__AF_PS_ERROR__' }"
        )
        res = run_powershell(script, timeout=90)
        text = (res.stdout or "").strip()
        if not res.ok or text == "__AF_PS_ERROR__" or not text:
            return ProbeResult(value=None, error="Windows Update Agent search failed or was blocked by policy")
        try:
            return ProbeResult(value=int(text), source="Windows Update Agent COM API")
        except ValueError:
            return ProbeResult(value=None, error=f"unexpected output: {text!r}")


@register
class CredentialGuardStatusPrimitive(Primitive):
    """Audit-only: enabling Credential Guard safely depends on hardware/VBS
    readiness that varies per machine; we report status but do not attempt
    to flip it on unattended (section 6 caution on authentication features)."""

    name = "win_credential_guard_status"

    def probe(self, params: dict) -> ProbeResult:
        data, err = _ps_json(
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | "
            "Select-Object -ExpandProperty SecurityServicesRunning"
        )
        if err:
            return ProbeResult(value=None, not_applicable=True, not_applicable_reason="Device Guard WMI class unavailable")
        running = data if isinstance(data, list) else ([data] if data else [])
        return ProbeResult(value=(1 in running), source="Win32_DeviceGuard", raw={"security_services_running": running})


@register
class EventLogConfigPrimitive(Primitive):
    """Modern (Vista+) event log sizing via the WinEvent API. Deliberately
    NOT the legacy HKLM\\...\\EventLog\\<Channel> MaxSize registry value,
    which the Windows Event Log service no longer authoritatively honors --
    using it would be exactly the kind of stale hardening myth section 3
    warns against."""

    name = "win_eventlog_config"

    def probe(self, params: dict) -> ProbeResult:
        channel = validate_token(params["channel"], r"^[A-Za-z0-9_\-/ ]+$")
        res = run_powershell(f"(Get-WinEvent -ListLog '{channel}').MaximumSizeInBytes", timeout=15)
        text = (res.stdout or "").strip()
        if not res.ok or not text:
            return ProbeResult(value=None, error=res.stderr.strip() or f"log channel '{channel}' not found")
        try:
            return ProbeResult(value=int(text), source="Get-WinEvent -ListLog", raw={"channel": channel})
        except ValueError:
            return ProbeResult(value=None, error=f"unexpected output {text!r}")

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        channel = validate_token(params["channel"], r"^[A-Za-z0-9_\-/ ]+$")
        target = int(params.get("value", expected_value if isinstance(expected_value, (int, float)) else 0))
        before = self.probe(params)
        script = (
            f"$log = Get-WinEvent -ListLog '{channel}'; "
            f"$log.MaximumSizeInBytes = {target}; $log.IsEnabled = $true; $log.SaveChanges()"
        )
        res = run_powershell(script, timeout=20)
        if not res.ok:
            raise RuntimeError(f"failed to set log size for '{channel}': {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=before.value, new_value=target)

    def rollback(self, params: dict, change) -> bool:
        channel = validate_token(params["channel"], r"^[A-Za-z0-9_\-/ ]+$")
        prev = int(change.previous_value)
        script = f"$log = Get-WinEvent -ListLog '{channel}'; $log.MaximumSizeInBytes = {prev}; $log.SaveChanges()"
        res = run_powershell(script, timeout=20)
        return res.ok


_AUDITPOL_PHRASE_TO_FLAGS = {
    "No Auditing": ("disable", "disable"),
    "Success": ("enable", "disable"),
    "Failure": ("disable", "enable"),
    "Success and Failure": ("enable", "enable"),
}


def _extract_auditpol_setting(text: str) -> str:
    import re as _re

    for line in text.splitlines():
        line = line.strip()
        if not line or "/" in line or line.lower().startswith(("system audit policy", "category")):
            continue
        m = _re.match(r"^(.+?)\s{2,}(No Auditing|Success and Failure|Success|Failure)\s*$", line)
        if m:
            return m.group(2)
    return "Unknown"


@register
class AuditPolicyPrimitive(Primitive):
    name = "win_audit_policy"

    def probe(self, params: dict) -> ProbeResult:
        subcategory = validate_token(params["subcategory"], r"^[A-Za-z ]+$")
        exe = resolve_binary("auditpol.exe")
        res = run([exe, "/get", f"/subcategory:{subcategory}"], timeout=15)
        if not res.ok:
            return ProbeResult(value=None, error=res.stderr.strip() or res.stdout.strip())
        setting = _extract_auditpol_setting(res.stdout)
        return ProbeResult(
            value=(setting == "Success and Failure"), source="auditpol /get", raw={"setting": setting}
        )

    def apply(self, params: dict, expected_value: Any) -> ApplyOutcome:
        subcategory = validate_token(params["subcategory"], r"^[A-Za-z ]+$")
        exe = resolve_binary("auditpol.exe")
        before = self.probe(params)
        prev_setting = (before.raw or {}).get("setting", "Unknown")
        res = run([exe, "/set", f"/subcategory:{subcategory}", "/success:enable", "/failure:enable"], timeout=15)
        if not res.ok:
            raise RuntimeError(f"auditpol /set failed: {res.stderr.strip() or res.stdout.strip()}")
        return ApplyOutcome(previous_value=prev_setting, new_value="Success and Failure")

    def rollback(self, params: dict, change) -> bool:
        subcategory = validate_token(params["subcategory"], r"^[A-Za-z ]+$")
        exe = resolve_binary("auditpol.exe")
        success, failure = _AUDITPOL_PHRASE_TO_FLAGS.get(str(change.previous_value), ("disable", "disable"))
        res = run(
            [exe, "/set", f"/subcategory:{subcategory}", f"/success:{success}", f"/failure:{failure}"], timeout=15
        )
        return res.ok


@register
class LapsStatusPrimitive(Primitive):
    """Audit-only: detects Windows LAPS policy presence. Enabling LAPS
    requires AD schema/config decisions outside AuditForge's scope."""

    name = "win_laps_status"

    def probe(self, params: dict) -> ProbeResult:
        value, exists = _read_reg("HKLM", r"SOFTWARE\Microsoft\Policies\LAPS", "BackupDirectory")
        legacy_value, legacy_exists = _read_reg("HKLM", r"SOFTWARE\Policies\Microsoft Services\AdmPwd", "AdmPwdEnabled")
        present = exists or legacy_exists
        return ProbeResult(
            value=present,
            source="registry:LAPS policy keys",
            raw={"windows_laps_backup_directory": value, "legacy_admpwd_enabled": legacy_value},
        )
