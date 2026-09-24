# AuditForge Control Reference

## Control counts (v0.1.0)

| OS | Controls | Primitives |
|---|---|---|
| Windows | 62 | 24 |
| Linux | 41 | 17 |
| macOS | 15 | 9 |

Run `auditforge audit` to see them evaluated live, or browse `auditforge/controls/<os>/*.yml` directly -- every file is a self-contained, human-readable record of one control.

## Control file schema

Every control file (validated against the JSON schema in `auditforge/core/control_loader.py:CONTROL_SCHEMA`) has:

| Field | Meaning |
|---|---|
| `control_id` | `AF-(WIN\|LNX\|MAC)-<CATEGORY>-<3 digits>`, e.g. `AF-WIN-SMB-001` |
| `title`, `description` | What it checks |
| `os` | `windows` \| `linux` \| `macos` |
| `applies_to` | Which specific distro/OS versions this is relevant to (informational; not yet enforced by the loader) |
| `category` | Groups controls in reports (`accounts`, `ssh`, `kernel`, `firewall`, ...) |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` -- also determines FAIL vs WARNING (see below) |
| `benchmark`, `benchmark_version`, `external_reference` | Where this control's guidance comes from -- see docs/SOURCES.md and docs/FRAMEWORK_MAPPING.md |
| `rationale` | Why this matters, in AuditForge's own words -- never copied benchmark text (see the CIS licensing note in docs/SOURCES.md) |
| `audit` | `{primitive: <name>, params: {...}}` -- what to run to check |
| `remediation` | Optional. `{primitive, params, reboot_required, service_restart_required}`. Absent entirely = audit-only, structurally (see docs/ARCHITECTURE.md) |
| `expected_value` | Plain value or the `{min/max/one_of/not}` mini-language |
| `possible_impact` | What could break if you apply this |
| `frameworks` | `{nist_800_53: [...], nist_800_63b: [...], disa_stig: [...], cis: [...], microsoft_baseline: [...], apple_guidance: [...]}` -- see docs/FRAMEWORK_MAPPING.md for what's actually populated vs. left as a documented gap |
| `management_detection` | Whether this control should check for `MANAGED_BY_ORGANIZATION` (only meaningful for Windows registry values under a `\Policies\` key today -- see docs/ARCHITECTURE.md) |
| `high_impact` | Requires `--allow-high-impact` on the CLI before `harden` will touch it |
| `tags`, `notes` | Free text |

## Severity determines FAIL vs. WARNING, not just report ordering

`medium`/`high`/`critical` mismatches report `FAIL`. `low`/`info` mismatches report `WARNING`. This is a deliberate mechanism, used throughout the control set to implement the project's anti-false-positive philosophy without needing a separate "confidence" field:

- **RDP/WinRM/SMB-client-NTLM-blocking/Screen-Sharing/File-Sharing/Remote-Login/rpcbind/Avahi-daemon "exposure reviewed" controls** are `severity: info` or `low` specifically so that "this is enabled" reports as a REVIEW signal (WARNING), never a false FAIL, on hosts where that's a legitimate operational choice.
- **Password-rotation-age controls** (`AF-WIN-ACCT-008`, `AF-LNX-AUTH-003`) are `severity: info` because NIST SP 800-63B-4 explicitly recommends against mandatory rotation -- a long/unlimited value is correct, not a gap, so it should never hard-FAIL.
- **Router-only kernel settings** (`AF-LNX-KRN-001` `ip_forward`, `AF-LNX-KRN-004` `send_redirects`) are `severity: low` because AuditForge cannot detect a router/gateway role automatically; a mismatch there is "please confirm this is intentional," not "this is broken."

## MANUAL_REVIEW controls (never PASS/FAIL)

These primitives set `ProbeResult.manual_review = True` unconditionally, because the fact pattern they gather cannot be judged pass/fail without human context:

- `AF-WIN-ACCT-002` (local Administrators group membership), `AF-LNX-FS-005` (SUID binary inventory), `AF-LNX-AUTH-005` (sudoers NOPASSWD scan), `AF-LNX-SVC-007` (firewall manager detection, only when *no* manager is found active).

## Audit-only-by-construction controls (no `remediation:` block exists at all)

FileVault (`AF-MAC-ENC-001`), SIP (`AF-MAC-SIP-001`), Gatekeeper (`AF-MAC-GK-001`), BitLocker (`AF-WIN-ENC-001`), Secure Boot (`AF-WIN-ENC-002`, `AF-LNX-BOOT-001`), TPM readiness (`AF-WIN-ENC-003`), Credential Guard (`AF-WIN-AUTH-005`), Defender Tamper Protection / Antivirus-active (`AF-WIN-DEF-007/008`), LAPS presence (`AF-WIN-AUTH-008`), Windows Update pending-count (`AF-WIN-UPD-002`), Linux/macOS package-update counts, and every `MANUAL_REVIEW` control above. There is no code path by which `harden`, `--allow-high-impact`, or any profile could cause AuditForge to change these.

## High-impact controls (require `--allow-high-impact`)

Windows: built-in Administrator disable (`AF-WIN-ACCT-003`), RDP disable (`AF-WIN-RDP-002`), WinRM disable (`AF-WIN-REMOTE-001`), Print Spooler disable (`AF-WIN-ASR-004`), SMB client NTLM blocking (`AF-WIN-SMB-005`). macOS: Remote Login disable (`AF-MAC-REMOTE-001`), Screen Sharing disable (`AF-MAC-REMOTE-003`), File Sharing disable (`AF-MAC-SHARE-001`). Every one of these can cut off a legitimate, currently-relied-upon access path -- see each control's `possible_impact` field.

## Connectivity guards (beyond high-impact gating)

- **Windows RDP** (`AF-WIN-RDP-001`, `AF-WIN-RDP-002`): `params.guard: current_session_rdp` makes the primitive check `$env:SESSIONNAME` and refuse to apply if the *current* AuditForge process is itself running inside the RDP session it would affect.
- **Linux SSH** (`AF-LNX-SSH-001`, `AF-LNX-SSH-002`): `params.guard: ssh_session` checks `SSH_CONNECTION`/`SSH_TTY` and refuses unless `AUDITFORGE_ALLOW_SSH_RISK=1` is explicitly set in the environment.
- **Not yet implemented** (documented gap, not silently assumed safe): a WinRM-session equivalent guard, and a macOS SSH-session equivalent guard for `AF-MAC-REMOTE-001`.

## Primitive catalog

See the module docstring and each `@register`-decorated class in:

- `auditforge/controls/windows/primitives.py` (24 primitives: registry DWORD/string, secedit local security policy, services, firewall profiles, optional features, SMB client/server config, Defender preferences/status, local users, local-admin count, NetBIOS, BitLocker/Secure-Boot/TPM/pending-reboot/pending-updates/Credential-Guard/LAPS status, event log config, audit policy)
- `auditforge/controls/linux/primitives.py` (17: sysctl, sshd option, systemd unit, file permissions, sticky bit, login.defs, pwquality/faillock, sudoers scan, firewall manager detection, ufw/firewalld status, SUID count, journald persistence, package updates, Secure Boot)
- `auditforge/controls/macos/primitives.py` (9: generic `defaults`, launchd service, FileVault/SIP/Gatekeeper status, Application Firewall state/stealth, systemsetup flag, MDM enrollment)

## Adding a new control

1. If an existing primitive covers what you need, write a new `controls/<os>/<ID>.yml` following the schema above -- no code change required.
2. If you need a new primitive, add a `Primitive` subclass to the relevant `primitives.py`, decorate it with `@register`, implement `probe()` (and `apply()`/`rollback()` if it should be remediable), and write a unit test using the mocking pattern in `tests/unit/test_windows_primitives.py` or `tests/unit/test_linux_primitives.py`.
3. Run `pytest tests/unit/test_control_loader.py` -- it validates every shipped control file's schema and primitive references automatically; a typo in a control ID, primitive name, or YAML structure fails CI immediately.
