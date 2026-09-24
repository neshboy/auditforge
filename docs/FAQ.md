# FAQ

**Will `auditforge audit` change anything on my machine?**
No. `audit` never calls a primitive's `apply()`. It's read-only by the same structural guarantee described in docs/ARCHITECTURE.md -- the code path simply doesn't exist for the audit command.

**Is it safe to run `harden` on a production server?**
Run `audit` first, review the report, then `harden --dry-run`, then `harden` with a profile that matches this machine's actual role (see docs/HARDENING.md). Nothing here removes the need for you to read the plan it prints before confirming. AuditForge's own safety limits (no sudoers editing, no blind RDP/SSH disable while connected through it, no disk-encryption enablement, high-impact gating) reduce risk but do not replace judgment about your specific environment.

**Why did AuditForge say a setting is MANAGED_BY_ORGANIZATION but it doesn't look GPO-managed to me?**
It might not be -- see the honest limitation in docs/ARCHITECTURE.md. The heuristic only works for Windows registry values under a `SOFTWARE\Policies\` key, combined with a domain-join/MDM-enrollment signal; it does not (yet) parse `gpresult` output to confirm which specific GPO set which specific value, and Linux/macOS have no equivalent detection at all yet.

**Why does a control report WARNING instead of FAIL (or vice versa)?**
Severity `medium`/`high`/`critical` mismatches are `FAIL`; `low`/`info` mismatches are `WARNING`. This is deliberate per-control, not a bug -- see docs/CONTROLS.md's "Severity determines FAIL vs. WARNING" section for the specific controls this matters for (RDP/WinRM/SMB exposure reviews, password-rotation-age, router-only kernel settings).

**A control says MANUAL_REVIEW. What do I do?**
Read the evidence in the report (the full member list, SUID path list, or sudoers line matches are all included) and make the call yourself. These controls (local-admin membership, SUID inventory, sudoers NOPASSWD scan) are intentionally never auto-judged pass/fail -- see docs/CONTROLS.md.

**Can AuditForge lock me out of SSH/RDP?**
Every SSH/RDP-affecting control is `high_impact: true` and requires `--allow-high-impact`. The Windows RDP and Linux SSH primitives additionally refuse to apply if the current AuditForge process is itself connected through the channel it would affect (`SESSIONNAME`/`SSH_CONNECTION` checks -- see docs/CONTROLS.md "Connectivity guards"). There is **no equivalent guard yet** for WinRM sessions or macOS SSH sessions -- be extra careful with `AF-WIN-REMOTE-001` and `AF-MAC-REMOTE-001` specifically.

**Does AuditForge support macOS for real?**
The macOS module was built from documented Apple CLI/`defaults` behavior and live-verified Apple documentation, but it has never been run against real Apple hardware or a macOS VM -- there was none available during this project's development. See docs/TEST_MATRIX.md. Treat it as a well-reasoned draft, not a validated feature, until someone runs it on a real Mac and reports back.

**Why doesn't AuditForge enforce password complexity rules (uppercase/number/symbol requirements)?**
Because current NIST SP 800-63B-4 guidance (verified July 2025, see docs/SOURCES.md) explicitly says verifiers **SHALL NOT** impose composition rules beyond a compromised-password blocklist check, and instead requires a 15-character minimum for single-factor passwords. AuditForge's password controls follow that, not the older "8-14 chars plus complexity" guidance many older baselines still use. See docs/CONTROLS.md and the `rationale` field on `AF-WIN-ACCT-006`/`AF-LNX-AUTH-001` for the full citation.

**Why doesn't AuditForge force periodic password rotation?**
Same reason -- SP 800-63B-4 recommends against it. AuditForge reports the current rotation-age setting as informational (`severity: info`, so a long/unlimited value is `PASS`, not `WARNING`) rather than penalizing an org that has deliberately moved away from forced rotation.

**Can I add my own controls without editing AuditForge's code?**
Yes, if an existing primitive covers what you need -- write a new YAML file following the schema in docs/CONTROLS.md. If you need a new primitive, see the same doc's "Adding a new control" section.

**Does AuditForge phone home, auto-update, or download anything at runtime?**
No. `auditforge framework status` reads local YAML files (`frameworks/*.yml`) that were populated by live research during development; it does not fetch anything over the network itself. Nothing in AuditForge downloads or executes remote code.

**Why is there no PDF report / Ubuntu Security Guide integration / DISA per-control ID mapping?**
Not implemented in v0.1 -- see the roadmap items listed in docs/ARCHITECTURE.md ("Known limitations") and docs/FRAMEWORK_MAPPING.md ("Why DISA per-control IDs are not included").
