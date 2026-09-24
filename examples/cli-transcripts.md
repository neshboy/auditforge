# Real CLI session transcripts

Captured during this project's own development and testing -- not fabricated. See `docs/TEST_MATRIX.md` for the full picture.

## `audit` -- live, this project's Windows 11 development machine

```
$ auditforge audit --profile audit_only --format json,html,markdown
Host:    MYCSOC
OS:      Microsoft Windows 11 Enterprise N 25H2 (AMD64)
Profile: audit_only
Score:   58.8%

  PASS                       30
  FAIL                       14
  WARNING                    7
  MANUAL_REVIEW              1
  MANAGED_BY_ORGANIZATION    8
  NOT_APPLICABLE             1
  ERROR                      1

Reports written:
  reports\audit-MYCSOC-20260924-092000.json
  reports\audit-MYCSOC-20260924-092000.html
  reports\audit-MYCSOC-20260924-092000.md
```

## `audit` -- live, disposable Ubuntu 24.04 Docker container (real systemd as PID 1)

```
$ auditforge audit
Audit took 5.6 s
Summary: {'PASS': 19, 'FAIL': 5, 'WARNING': 7, 'NOT_APPLICABLE': 8, 'MANUAL_REVIEW': 2, 'MANAGED_BY_ORGANIZATION': 0, 'ERROR': 0} score= 61.3

AF-LNX-SSH-001     FAIL       without-password   Expected {'one_of': ['no', 'prohibit-password'...
AF-LNX-SSH-002     FAIL       yes                Expected 'no', found 'yes'
AF-LNX-SVC-008     FAIL       False              Expected True, found False
...
```

## Full `harden` -> transaction -> post-audit -> `rollback` -> post-rollback pipeline (live, same container)

```
Targeting ['AF-LNX-KRN-008', 'AF-LNX-SSH-004', 'AF-LNX-SSH-005', 'AF-LNX-SVC-008']
PLAN to_apply: ['AF-LNX-KRN-008', 'AF-LNX-SSH-004', 'AF-LNX-SSH-005', 'AF-LNX-SVC-008']
PLAN skipped: []
TX ID: AF-20260924-091418-AF4827
 applied: ApplyResultItem(control_id='AF-LNX-KRN-008', outcome='applied', message='')
 applied: ApplyResultItem(control_id='AF-LNX-SSH-004', outcome='applied', message='')
 applied: ApplyResultItem(control_id='AF-LNX-SSH-005', outcome='applied', message='')
 applied: ApplyResultItem(control_id='AF-LNX-SVC-008', outcome='applied', message='')

--- post-audit of targets ---
AF-LNX-KRN-008     PASS       1
AF-LNX-SSH-004     PASS       'no'
AF-LNX-SSH-005     PASS       '4'
AF-LNX-SVC-008     PASS       True

--- rollback ---
  RollbackItemResult(control_id='AF-LNX-SVC-008', primitive='linux_ufw_status', restored=True, message='restored previous value')
  RollbackItemResult(control_id='AF-LNX-SSH-005', primitive='linux_sshd_option', restored=True, message='restored previous value')
  RollbackItemResult(control_id='AF-LNX-SSH-004', primitive='linux_sshd_option', restored=True, message='restored previous value')
  RollbackItemResult(control_id='AF-LNX-KRN-008', primitive='linux_sysctl', restored=True, message='restored previous value')
all_restored: True

--- post-rollback audit ---
AF-LNX-KRN-008     WARNING    0
AF-LNX-SSH-004     WARNING    'yes'
AF-LNX-SSH-005     WARNING    '6'
AF-LNX-SVC-008     FAIL       False
```

Note the post-rollback values exactly match the pre-harden values (`0`/`'yes'`/`'6'`/`False`) -- rollback restored the original state precisely, confirmed by a second independent audit rather than just trusting the rollback function's own "success" report.

## `harden --dry-run` -- live, this project's Windows 11 development machine (no changes made)

```
$ auditforge harden --profile workstation --dry-run
Controls that WOULD be changed: 15
  [medium  ] AF-WIN-ACCT-005    Account lockout duration is at least 15 minutes
             current=10 -> expected={'min': 15}
  [high    ] AF-WIN-ACCT-006    Minimum local password length meets current NIST guidance (>=15 characters)
             current=0 -> expected={'min': 15}
  [low     ] AF-WIN-ACCT-007    Password history remembers at least 5 previous passwords
             current=0 -> expected={'min': 5}
  [low     ] AF-WIN-ASR-003     NetBIOS over TCP/IP is disabled where not required
             current=False -> expected=True
  [high    ] AF-WIN-AUTH-002    LAN Manager authentication level restricts legacy LM/NTLMv1
             current=3 -> expected={'min': 5}
  [medium  ] AF-WIN-AUTH-006    Cached domain logon count is limited
             current='10' -> expected={'max': 4}
  [medium  ] AF-WIN-DEF-004     Controlled Folder Access is enabled or auditing
             current=0 -> expected={'one_of': ['Enabled', 'AuditMode']}
  [medium  ] AF-WIN-DEF-005     Defender Network Protection is enabled or auditing
             current=0 -> expected={'one_of': ['Enabled', 'AuditMode']}
  [high    ] AF-WIN-FW-004      Public profile default inbound action is Block
             current=0 -> expected={'one_of': ['Block']}
  [medium  ] AF-WIN-LOG-002     Security event log has adequate maximum size
             current=20971520 -> expected={'min': 201326592}
  [low     ] AF-WIN-LOG-003     PowerShell operational log has adequate maximum size
             current=15728640 -> expected={'min': 67108864}
  [medium  ] AF-WIN-LOG-004     Process Creation auditing is enabled
             current=False -> expected=True
  [medium  ] AF-WIN-LOG-006     Account Lockout auditing is enabled
             current=False -> expected=True
  [low     ] AF-WIN-RDP-003     Remote Assistance is disabled unless needed
             current=1 -> expected=0
  [low     ] AF-WIN-SMB-004     SMB encryption is enabled where supported
             current=False -> expected=True

Controls skipped: 3
  AF-WIN-AUTH-008    LAPS (local administrator password management) is present  -- no automated remediation (manual review only)
  AF-WIN-ENC-001     BitLocker volume protection is on (audit only)  -- no automated remediation (manual review only)
  AF-WIN-ENC-002     Secure Boot is enabled (audit only)  -- no automated remediation (manual review only)

[DRY RUN] No changes were applied.
```

(High-impact and audit-only-by-construction controls like RDP/WinRM disable, Credential Guard, and Print Spooler don't appear here at all -- either they were already PASS on this machine, or the `workstation` profile excludes them, or they have no `remediation:` block to begin with. See `docs/CONTROLS.md`.)
