"""Environment detection: which OS/version we're on, and whether the device
looks centrally managed (AD/Entra/Intune/GPO, MDM, or Linux config
management). Controls consult ManagementInfo before flagging a setting that
an organization's management platform already owns -- see section 11 of the
project spec ("do not fight the management platform").
"""

from __future__ import annotations

import dataclasses
import os
import platform

from auditforge.core.models import OperatingSystem
from auditforge.utils.safe_exec import run, run_powershell


@dataclasses.dataclass
class EnvironmentInfo:
    os: OperatingSystem
    os_name: str  # e.g. "Windows 11", "Ubuntu", "macOS"
    os_version: str  # e.g. "24H2", "24.04", "15.4"
    build: str = ""
    is_server: bool = False
    architecture: str = ""  # "arm64" | "x86_64" | ...
    hostname: str = ""


@dataclasses.dataclass
class ManagementInfo:
    managed: bool
    sources: tuple[str, ...] = ()
    details: dict = dataclasses.field(default_factory=dict)


def detect_environment() -> EnvironmentInfo:
    system = platform.system()
    hostname = platform.node()
    if system == "Windows":
        return _detect_windows(hostname)
    if system == "Darwin":
        return _detect_macos(hostname)
    if system == "Linux":
        return _detect_linux(hostname)
    return EnvironmentInfo(
        os=OperatingSystem.LINUX,
        os_name=system,
        os_version=platform.release(),
        hostname=hostname,
    )


def _detect_windows(hostname: str) -> EnvironmentInfo:
    result = run_powershell(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,BuildNumber,ProductType | ConvertTo-Json -Compress"
    )
    caption, build, product_type = platform.win32_ver()[0] or "Windows", "", "1"
    display_version = ""
    try:
        import json

        if result.ok and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            caption = data.get("Caption", caption) or caption
            build = str(data.get("BuildNumber", ""))
            product_type = str(data.get("ProductType", "1"))
    except Exception:
        pass
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            try:
                display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except OSError:
                display_version = ""
    except Exception:
        pass
    is_server = product_type != "1"
    return EnvironmentInfo(
        os=OperatingSystem.WINDOWS,
        os_name=caption.strip(),
        os_version=display_version or platform.win32_ver()[1],
        build=build or platform.win32_ver()[3],
        is_server=is_server,
        architecture=platform.machine(),
        hostname=hostname,
    )


def _detect_macos(hostname: str) -> EnvironmentInfo:
    ver, _, machine = platform.mac_ver()
    return EnvironmentInfo(
        os=OperatingSystem.MACOS,
        os_name="macOS",
        os_version=ver,
        architecture=machine or platform.machine(),
        hostname=hostname,
    )


def _read_os_release() -> dict:
    data = {}
    path = "/etc/os-release"
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or "=" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                data[key] = value.strip('"')
    return data


def _detect_linux(hostname: str) -> EnvironmentInfo:
    rel = _read_os_release()
    return EnvironmentInfo(
        os=OperatingSystem.LINUX,
        os_name=rel.get("NAME", "Linux"),
        os_version=rel.get("VERSION_ID", platform.release()),
        architecture=platform.machine(),
        hostname=hostname,
    )


def detect_management(env: EnvironmentInfo) -> ManagementInfo:
    if env.os == OperatingSystem.WINDOWS:
        return _detect_windows_management()
    if env.os == OperatingSystem.MACOS:
        return _detect_macos_management()
    return _detect_linux_management()


def _detect_windows_management() -> ManagementInfo:
    sources = []
    details = {}
    ps = run_powershell(
        "try { dsregcmd /status } catch { '' }"
    )
    text = ps.stdout or ""
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in ("AzureAdJoined", "EnterpriseJoined", "DomainJoined") and value.upper() == "YES":
            sources.append(key)
            details[key] = value
        if key in ("MdmUrl", "MdmTenantId") and value and value.upper() not in ("NO", ""):
            sources.append("Intune/MDM")
            details[key] = value
    gp = run_powershell(
        "(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History' "
        "-ErrorAction SilentlyContinue | Measure-Object).Count"
    )
    try:
        if gp.ok and int(gp.stdout.strip() or "0") > 0:
            sources.append("GroupPolicy")
    except ValueError:
        pass
    return ManagementInfo(managed=bool(sources), sources=tuple(dict.fromkeys(sources)), details=details)


def _detect_macos_management() -> ManagementInfo:
    sources = []
    details = {}
    res = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=15)
    if res.ok:
        details["profiles_status"] = res.stdout.strip()
        if "MDM enrollment: Yes" in res.stdout:
            sources.append("MDM")
    return ManagementInfo(managed=bool(sources), sources=tuple(sources), details=details)


_LINUX_MGMT_MARKERS = {
    "/etc/ansible": "Ansible",
    "/etc/puppetlabs": "Puppet",
    "/etc/chef": "Chef",
    "/etc/salt": "SaltStack",
    "/var/lib/ubuntu-advantage": "Ubuntu Pro",
    "/etc/sssd/sssd.conf": "SSSD (possible domain join)",
    "/etc/ipa/default.conf": "FreeIPA/RHEL IdM",
}


def _detect_linux_management() -> ManagementInfo:
    sources = [label for path, label in _LINUX_MGMT_MARKERS.items() if os.path.exists(path)]
    return ManagementInfo(managed=bool(sources), sources=tuple(sources), details={})
