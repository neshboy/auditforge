# AuditForge Security Assessment: MYCSOC

- **OS:** Microsoft Windows 11 Enterprise N 25H2 (AMD64)
- **Profile:** audit_only
- **Generated:** 2026-09-24T09:52:24.890110+00:00
- **Centrally managed:** No
- **Overall score:** 58.8%

## Summary

| Status | Count |
|---|---|
| PASS | 30 |
| FAIL | 14 |
| WARNING | 7 |
| NOT_APPLICABLE | 1 |
| MANUAL_REVIEW | 1 |
| MANAGED_BY_ORGANIZATION | 8 |
| ERROR | 1 |

## Findings

### AF-WIN-ACCT-006: Minimum local password length meets current NIST guidance (>=15 characters)

- **Status:** FAIL
- **Severity:** high
- **Observed:** 0
- **Expected:** >= 15
- **Why:** NIST SP 800-63B-4 Sec. 3.1.1.1-3.1.1.2 (verified by direct PDF read, see docs/SOURCES.md) SHALL requires verifiers to enforce a minimum of 15 characters for passwords used as a single authentication factor (8 characters minimum is only acceptable when the password is one factor of MFA), SHOULD support at least 64 characters, and explicitly SHALL NOT impose composition/complexity rules beyond a compromised-password blocklist check. This supersedes the older, widely-cited "8-14 chars plus complexity" guidance -- see section 3 of the project spec ("do not blindly implement old hardening advice") and AF-WIN-ACCT-007's notes.
- **Reference:** https://csrc.nist.gov/pubs/sp/800/63/b/4/final
- **Remediation available:** YES

### AF-WIN-AUTH-002: LAN Manager authentication level restricts legacy LM/NTLMv1

- **Status:** FAIL
- **Severity:** high
- **Observed:** 3
- **Expected:** >= 5
- **Why:** LM and NTLMv1 use weak, crackable challenge/response schemes. Requiring NTLMv2-only (and refusing the legacy variants) removes an easy downgrade target, while stopping short of Microsoft's broader in-progress NTLM deprecation roadmap (see docs/SOURCES.md), which is not yet default-on for currently supported releases and is out of scope for this control.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-pth-attacks
- **Remediation available:** YES

### AF-WIN-ENC-001: BitLocker volume protection is on (audit only)

- **Status:** FAIL
- **Severity:** high
- **Observed:** Off
- **Expected:** On
- **Why:** Full-disk encryption protects data at rest from offline access if a device is lost or stolen. AuditForge deliberately never enables encryption automatically -- per section 6 of the project spec, doing so without first protecting the recovery key (e.g. in AD/Entra or a printed recovery sheet) risks irrecoverable data loss.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
- **Remediation available:** NO

### AF-WIN-ENC-002: Secure Boot is enabled (audit only)

- **Status:** FAIL
- **Severity:** high
- **Observed:** False
- **Expected:** True
- **Why:** Secure Boot is foundational to the modern Windows boot-integrity chain (and a prerequisite for several VBS-based protections). AuditForge cannot change firmware settings and does not attempt to.
- **Reference:** https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot
- **Remediation available:** NO

### AF-WIN-FW-004: Public profile default inbound action is Block

- **Status:** FAIL
- **Severity:** high
- **Observed:** 0
- **Expected:** one of: Block
- **Why:** Default-block for unsolicited inbound traffic on untrusted networks is a foundational network-exposure control.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/
- **Remediation available:** YES

### AF-WIN-ACCT-005: Account lockout duration is at least 15 minutes

- **Status:** FAIL
- **Severity:** medium
- **Observed:** 10
- **Expected:** >= 15
- **Why:** A very short lockout duration provides little throttling benefit against automated guessing; 15+ minutes is a widely used minimum baseline.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings
- **Remediation available:** YES

### AF-WIN-ASR-004: Print Spooler is disabled where printing is not required

- **Status:** FAIL
- **Severity:** medium
- **Observed:** Automatic
- **Expected:** Disabled
- **Why:** The Print Spooler has repeatedly been a source of critical remote/local privilege-escalation vulnerabilities (PrintNightmare and related CVEs). Servers and workstations that do not print have no reason to run it.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/print
- **Remediation available:** YES

### AF-WIN-AUTH-006: Cached domain logon count is limited

- **Status:** FAIL
- **Severity:** medium
- **Observed:** 10
- **Expected:** <= 4
- **Why:** Cached logon credential material is a target for offline cracking on lost/stolen devices. A small cache (e.g. 4) still allows normal offline laptop use while limiting exposure.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- **Remediation available:** YES

### AF-WIN-AUTH-008: LAPS (local administrator password management) is present

- **Status:** FAIL
- **Severity:** medium
- **Observed:** False
- **Expected:** True
- **Why:** Without LAPS, local administrator passwords are often identical across many machines, so compromising one grants lateral movement to many others. AuditForge only detects LAPS presence; deploying LAPS requires AD schema/Entra configuration decisions outside this tool's scope.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- **Remediation available:** NO

### AF-WIN-DEF-004: Controlled Folder Access is enabled or auditing

- **Status:** FAIL
- **Severity:** medium
- **Observed:** 0
- **Expected:** one of: Enabled, AuditMode
- **Why:** Controlled Folder Access blocks unrecognized processes from modifying files in protected folders, a strong mitigation against ransomware encryption behavior.
- **Reference:** https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders
- **Remediation available:** YES

### AF-WIN-DEF-005: Defender Network Protection is enabled or auditing

- **Status:** FAIL
- **Severity:** medium
- **Observed:** 0
- **Expected:** one of: Enabled, AuditMode
- **Why:** Network Protection stops connections to malicious domains/IPs (phishing, C2, exploit-hosting sites) even if a malicious process is not yet detected by signature/behavior analysis.
- **Reference:** https://learn.microsoft.com/en-us/defender-endpoint/network-protection
- **Remediation available:** YES

### AF-WIN-LOG-002: Security event log has adequate maximum size

- **Status:** FAIL
- **Severity:** medium
- **Observed:** 20971520
- **Expected:** >= 201326592
- **Why:** A too-small Security log can wrap and lose evidence within hours on a busy system, especially once auditing is turned up (see AF-WIN-LOG-001, 004-006). This control uses the modern Get-WinEvent/EventLogConfiguration API rather than the legacy, no-longer-authoritative HKLM\...\EventLog\Security\MaxSize registry value (see the primitive's own docstring) -- using that legacy key would itself be exactly the kind of stale hardening myth the project spec warns against.
- **Reference:** https://learn.microsoft.com/en-us/windows/win32/wes/eventlog-key
- **Remediation available:** YES

### AF-WIN-LOG-004: Process Creation auditing is enabled

- **Status:** FAIL
- **Severity:** medium
- **Observed:** False
- **Expected:** True
- **Why:** Without this audit subcategory enabled, no 4688 process-creation events are generated regardless of the command-line-inclusion setting.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- **Remediation available:** YES

### AF-WIN-LOG-006: Account Lockout auditing is enabled

- **Status:** FAIL
- **Severity:** medium
- **Observed:** False
- **Expected:** True
- **Why:** Lockout events are a strong signal of active password-guessing attempts against one or more accounts.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-account-logon-events
- **Remediation available:** YES

### AF-WIN-UPD-002: No outstanding software updates (audit only)

- **Status:** ERROR
- **Severity:** medium
- **Observed:** None
- **Expected:** <= 0
- **Why:** Unpatched software is one of the most common real-world attack vectors. AuditForge deliberately does not auto-install updates unattended (that requires reboot orchestration and change-control outside this tool's scope) -- this is audit-only, surfaced for manual patching action.
- **Reference:** https://learn.microsoft.com/en-us/windows/deployment/update/
- **Remediation available:** NO

### AF-WIN-ACCT-007: Password history remembers at least 5 previous passwords

- **Status:** WARNING
- **Severity:** low
- **Observed:** 0
- **Expected:** >= 5
- **Why:** A small password-history requirement stops the common "change it and change it right back" workaround without imposing NIST 800-63B's discouraged practice of frequent forced rotation.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings
- **Remediation available:** YES

### AF-WIN-ASR-003: NetBIOS over TCP/IP is disabled where not required

- **Status:** WARNING
- **Severity:** low
- **Observed:** False
- **Expected:** True
- **Why:** NetBIOS is a legacy name-resolution protocol superseded by DNS; leaving it enabled widens the same credential-relay attack surface as LLMNR.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-pth-attacks
- **Remediation available:** YES

### AF-WIN-LOG-003: PowerShell operational log has adequate maximum size

- **Status:** WARNING
- **Severity:** low
- **Observed:** 15728640
- **Expected:** >= 67108864
- **Why:** Script Block Logging is only useful if the log capacity is large enough to retain events long enough to be reviewed or shipped to a SIEM.
- **Reference:** https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- **Remediation available:** YES

### AF-WIN-RDP-003: Remote Assistance is disabled unless needed

- **Status:** WARNING
- **Severity:** low
- **Observed:** 1
- **Expected:** 0
- **Why:** Remote Assistance adds another remote-control surface; if a help-desk workflow doesn't use it, it should be off.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-overview
- **Remediation available:** YES

### AF-WIN-SMB-004: SMB encryption is enabled where supported

- **Status:** WARNING
- **Severity:** low
- **Observed:** False
- **Expected:** True
- **Why:** Verified research confirms SMB encryption is opt-in, not a Windows default, on every currently supported release. This is an optional hardening step (low severity: a mismatch reports WARNING, not FAIL) -- enabling it is a deliberate choice with real compatibility/performance trade-offs, not a "should always be on" baseline expectation.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security
- **Remediation available:** YES

### AF-WIN-RDP-002: Remote Desktop exposure is reviewed (informational)

- **Status:** WARNING
- **Severity:** info
- **Observed:** 0
- **Expected:** 1
- **Why:** Per the project's false-positive policy, "RDP enabled" is a REVIEW signal, not an automatic FAIL -- see section 34 of the project spec. Severity is deliberately "info" so a mismatch here reports WARNING, and remediation is gated behind --allow-high-impact plus a live-session guard.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-overview
- **Remediation available:** YES

### AF-WIN-SMB-005: SMB client NTLM blocking is considered (informational)

- **Status:** WARNING
- **Severity:** info
- **Observed:** False
- **Expected:** True
- **Why:** This is a brand-new (2025/2026) opt-in capability, not yet a default or a mature baseline expectation, and enabling it can break legitimate non-domain-joined SMB servers that still require NTLM. AuditForge reports it as informational context only (severity=info -> WARNING, never FAIL) rather than a hardening requirement.
- **Reference:** https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking
- **Remediation available:** YES

### AF-WIN-ACCT-002: Local Administrators group membership review

- **Status:** MANUAL_REVIEW
- **Severity:** medium
- **Observed:** 3
- **Expected:** True
- **Why:** Excess or stale administrator accounts widen the blast radius of any single compromised credential. This is intentionally a MANUAL_REVIEW finding, not an automatic FAIL, per the project's false-positive policy.
- **Reference:** https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts
- **Remediation available:** NO
