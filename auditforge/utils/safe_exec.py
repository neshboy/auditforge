"""Hardened subprocess wrapper.

Threat model (see docs/ARCHITECTURE.md "Security review of AuditForge
itself"): every probe/remediation primitive shells out to a system tool.
To keep that safe:

  * argv lists only, never shell=True / string concatenation into a shell.
  * PowerShell scripts are passed on stdin, never interpolated into -Command
    strings, so control-file text can never break out of the script context.
  * Binaries are resolved to absolute, known-good paths first (System32,
    /usr/sbin, /sbin, ...) before falling back to PATH lookup, to reduce
    PATH-hijacking risk.
  * Every call has a timeout; nothing blocks the engine forever.
  * validate_token() gives primitives a cheap allowlist check on any value
    that will be interpolated into an argv element or PowerShell script,
    even though those values come from our own trusted control YAML --
    defense in depth against a corrupted or malicious control file.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
import subprocess
from typing import Optional, Sequence

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:\\/\-]+$")

_KNOWN_PATHS = {
    "powershell.exe": (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",),
    "reg.exe": (r"C:\Windows\System32\reg.exe",),
    "sc.exe": (r"C:\Windows\System32\sc.exe",),
    "secedit.exe": (r"C:\Windows\System32\secedit.exe",),
    "auditpol.exe": (r"C:\Windows\System32\auditpol.exe",),
    "netsh.exe": (r"C:\Windows\System32\netsh.exe",),
    "manage-bde.exe": (r"C:\Windows\System32\manage-bde.exe",),
    "sysctl": ("/usr/sbin/sysctl", "/sbin/sysctl"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "sshd": ("/usr/sbin/sshd",),
    "ufw": ("/usr/sbin/ufw",),
    "firewall-cmd": ("/usr/bin/firewall-cmd",),
    "nft": ("/usr/sbin/nft", "/sbin/nft"),
    "defaults": ("/usr/bin/defaults",),
    "fdesetup": ("/usr/bin/fdesetup",),
    "csrutil": ("/usr/bin/csrutil", "/usr/sbin/csrutil"),
    "spctl": ("/usr/sbin/spctl",),
    "profiles": ("/usr/bin/profiles",),
    "pmset": ("/usr/bin/pmset",),
    "systemsetup": ("/usr/sbin/systemsetup",),
    "socketfilterfw": ("/usr/libexec/ApplicationFirewall/socketfilterfw",),
    "sysadminctl": ("/usr/sbin/sysadminctl",),
}


class UnsafeValueError(ValueError):
    pass


def validate_token(value: str, pattern: Optional[str] = None) -> str:
    """Reject values containing shell/PowerShell metacharacters before they
    reach an argv list or a generated script. Raises UnsafeValueError."""
    if value is None:
        raise UnsafeValueError("value is required")
    s = str(value)
    rx = re.compile(pattern) if pattern else _TOKEN_RE
    if not rx.match(s):
        raise UnsafeValueError(f"value failed safety validation: {s!r}")
    return s


def resolve_binary(name: str) -> str:
    for candidate in _KNOWN_PATHS.get(name, ()):
        import os

        if os.path.isfile(candidate):
            return candidate
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(f"required binary not found: {name}")


@dataclasses.dataclass
class CommandResult:
    argv: tuple
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run(argv: Sequence[str], timeout: int = 20, input_text: Optional[str] = None) -> CommandResult:
    argv = tuple(argv)
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(argv, proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(argv, -1, exc.stdout or "", exc.stderr or "", timed_out=True)
    except FileNotFoundError as exc:
        return CommandResult(argv, -1, "", str(exc))


def run_powershell(script: str, timeout: int = 30) -> CommandResult:
    """Run a PowerShell script passed via stdin (never via -Command string
    interpolation) so control-supplied text cannot escape into new
    statements or use $()/backtick injection against the invocation itself."""
    exe = resolve_binary("powershell.exe")
    argv = (
        exe,
        "-NoProfile",
        "-NonInteractive",
        "-NoLogo",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "-",
    )
    return run(argv, timeout=timeout, input_text=script)
