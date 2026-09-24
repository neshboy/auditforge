# Hardening with AuditForge

**Read this before running `auditforge harden` on anything you care about.**

## The sequence `harden` actually follows

1. Detect environment (OS, version, architecture, management status).
2. Run a full audit of the selected controls.
3. Compute the plan: which FAIL/WARNING findings have a `remediation:` block, aren't excluded by the active profile, aren't `MANAGED_BY_ORGANIZATION`, and (for `high_impact: true` controls) whether `--allow-high-impact` was passed.
4. Print the plan (control ID, current value, expected value, possible impact, reboot/service-restart flags) for every control that *would* change, and every control that was *skipped* with the reason.
5. If `--dry-run` was passed, or the active profile has `audit_only: true`, stop here. Nothing is touched.
6. Otherwise, unless `--yes` was passed, prompt for a `yes` confirmation naming the hostname and the number of changes.
7. Begin a transaction (unique ID, manifest on disk).
8. Apply each planned change. A failure on one control is recorded and does **not** abort the remaining controls (see `core/engine.py:apply_harden`) -- each primitive's `apply()` is independent and, where the underlying mechanism supports it (sshd, sysctl), self-validates before committing (e.g. `sshd -t` before reload).
9. Re-probe every applied control; record whether it actually reads back as compliant now.
10. Run a full post-hardening audit and print the before/after summary.
11. Print the transaction ID and the exact `auditforge rollback <id>` command to undo it.

## Always do this first

```
auditforge audit --profile audit_only
```

This is read-only by construction (`audit_only: true` in `profiles/audit_only.yml` -- see `cli.py:cmd_harden`, the check happens before any `apply()` call regardless of what other flags you pass). Review the HTML report. Understand what would change before you ask AuditForge to change it.

Then:

```
auditforge harden --profile workstation --dry-run
```

Dry-run shows you the exact same plan `harden` would execute, with zero changes made.

## Profiles

| Profile | `allow_high_impact` | `audit_only` | Notes |
|---|---|---|---|
| `audit_only` | false | **true** | Never applies anything, no matter what else you pass |
| `workstation` | false | false | Home workstation; excludes Print Spooler disable |
| `corporate` | false | false | Assumes centralized management may already own some settings |
| `developer` | false | false | Currently identical to `corporate` -- see its own notes field |
| `server` | false | false | Excludes Print Spooler disable; recommends per-role customization |
| `public_server` | false | false | Evaluates `severity: info` controls too (severity_floor: info) |
| `strict` | **true** | false | Allows high-impact controls once you *also* pass `--allow-high-impact` on the CLI |

Profiles filter by `exclude_controls`, `exclude_categories`, and `severity_floor` (see `core/profile_loader.py:apply_profile_filter`). `allow_high_impact: true` on a profile does not bypass the CLI flag -- both `--allow-high-impact` and the profile's own setting are OR'd together in `cli.py:cmd_harden`, so `strict` still needs `--allow-high-impact` explicitly on the command line for its own gate to matter, but a profile *can* pre-authorize it for automated/CI use if you deliberately want that.

## What `harden` will never do, regardless of profile or flags

(See docs/CONTROLS.md "Audit-only-by-construction controls" for the exhaustive list, and docs/ARCHITECTURE.md for why this is structural, not a runtime check that could have a bug in it.)

- Enable disk encryption (BitLocker/FileVault) without a pre-existing recovery-key plan.
- Change System Integrity Protection or Gatekeeper's on/off switch.
- Edit `/etc/sudoers` or `/etc/sudoers.d/*` in any way.
- Disable RDP/WinRM/SSH while the current AuditForge process is itself connected through that channel (Windows RDP and Linux SSH only -- see docs/CONTROLS.md for the macOS/WinRM gaps).
- Remove or reduce local Administrators/sudo group membership.
- Flush, replace, or delete existing firewall rules (ufw/firewalld/Windows Firewall enable-only; nftables/iptables rules are never touched at all).
- Install, uninstall, or upgrade any package.

## Reboot / service restart

Controls with `reboot_required: true` (PowerShell v2 removal, UAC toggle, LSASS RunAsPPL, Windows optional-feature changes) or `service_restart_required: true` (RDP NLA, event-log-config changes) are applied immediately but may not take full effect until that reboot/restart happens. AuditForge never reboots or force-restarts a service on your behalf -- that scheduling decision is always yours. Check the `harden` output and the HTML report's per-finding "Remediation" line for these flags before considering a hardening run "done."

## After hardening

```
auditforge verify [transaction_id]
```

Re-audits exactly the controls a transaction touched and reports configuration drift -- useful after a GPO refresh, a config-management run, or simply time passing, to confirm your hardening is still in effect.

```
auditforge rollback <transaction_id>
auditforge rollback --list
```

Undoes a transaction, replaying its changes in reverse. See docs/ROLLBACK.md for exactly what is and isn't guaranteed to be perfectly reversible.
