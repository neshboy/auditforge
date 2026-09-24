# Rollback

## Basic usage

```
auditforge rollback --list                     # see available transactions
auditforge rollback AF-20260924-153533-A7F21C   # undo one
```

Every `harden` run gets a transaction ID in the form `AF-YYYYMMDD-HHMMSS-XXXXXX` (date/time it started, plus a random hex suffix -- see `rollback/transaction.py:new_transaction_id`). The manifest for each transaction lives under:

- Windows: `%ProgramData%\AuditForge\transactions\<id>\manifest.json` (falls back to `%LOCALAPPDATA%\AuditForge` if `%ProgramData%` isn't writable)
- Linux/macOS: `/var/lib/auditforge/transactions/<id>/manifest.json` (falls back to `~/.auditforge` if that isn't writable)

Override with the `AUDITFORGE_STATE_DIR` environment variable.

## What's in a transaction manifest

Transaction ID, hostname, executing account, OS name/version, profile, start/finish timestamps, dry-run flag, status (`in_progress` / `complete` / `partial` / `rolled_back`), pre- and post-hardening audit summaries, and one `ChangeRecord` per control actually applied: control ID, primitive name, params, previous value, new value, timestamp. **No secrets are ever recorded** -- every primitive AuditForge ships only reads/writes configuration state (booleans, enums, integers, policy values), never credential material; this is enforced by construction and spot-checked in `tests/unit/test_transaction.py`.

## How rollback works

`rollback/executor.py:rollback_transaction` loads the manifest, then replays every `ChangeRecord` **in reverse order**, calling that control's primitive's `rollback(params, change)` with the recorded `previous_value`. Each item's outcome (`restored: bool`, a message) is recorded and printed independently -- one item failing does not stop the rest from being attempted. The transaction's final status becomes `rolled_back` only if every item restored successfully; otherwise it's `partial`, and the CLI's exit code reflects that (`1` for partial, `0` for full).

## What's exactly reversible

Anything managed through a dedicated drop-in file AuditForge owns outright: sysctl (`/etc/sysctl.d/90-auditforge.conf`), sshd options (`/etc/ssh/sshd_config.d/00-auditforge.conf`), journald storage (`/etc/systemd/journald.conf.d/90-auditforge.conf`). Rollback removes AuditForge's own line/file and re-validates (for sshd, `sshd -t` before reload), reverting to whatever the rest of the system's configuration already specified -- because AuditForge never touched anything else in the first place.

Registry values (Windows), `login.defs`/`pwquality.conf`/`faillock.conf` (Linux), and `defaults` domains (macOS) restore the exact previous value, or delete the key entirely if it didn't exist before (`{"__absent__": true}` sentinel -- see `docs/ARCHITECTURE.md`).

## What's only best-effort or explicitly not reversible

- **`win_secedit_policy`** (local security policy): rollback re-exports, patches the one line back to its previous value, and re-applies the *entire* policy area -- same export-modify-reapply technique as `apply()`, for the same reason (a partial `/configure` would reset unspecified settings). This is well-tested logically but has the same dependency on `secedit`'s own correctness as the forward direction.
- **`win_optional_feature`** / PowerShell-v2 removal and similar: reversible in principle (re-enable the feature), but Windows optional features generally require a **reboot** to fully take effect either direction; rollback issues the reversing command but does not reboot for you.
- **`win_netbios_status`**: rollback is explicitly best-effort -- it restores the *first* adapter's previously-recorded value to all adapters, not necessarily each adapter's own prior value, since the primitive doesn't track per-adapter history separately. See the class docstring in `controls/windows/primitives.py`.
- **`linux_faillock`/`linux_pwquality`/Linux `login_defs`** with a previously-absent key: rollback intentionally does **not** delete the line it added (`if isinstance(prev, dict) and prev.get("__absent__"): return True` -- see the primitive) on the reasoning that leaving a now-explicit value in place is harmless, whereas deleting it back to implicit/default is not meaningfully safer and adds rollback complexity. If you need the line gone entirely, remove it manually.
- **Anything in `harden` that a user or another process changed again in the meantime**: rollback restores AuditForge's recorded previous value, not necessarily "whatever the system's state was going to be anyway" if something else modified the same setting after AuditForge's `harden` run. Run `auditforge verify` first if you're not sure.

## What is never touched at all, so there is nothing to roll back

BitLocker/FileVault, SIP, Gatekeeper's on/off switch, sudoers, existing firewall rules (nftables/iptables specifically; ufw/firewalld are only ever *enabled*, never disabled by rollback beyond restoring the pre-`harden` active/inactive state), local Administrators/sudo group membership. See docs/CONTROLS.md for the complete list and why.

## If a rollback partially fails

The CLI prints exactly which control(s) failed to restore and why (the primitive's own error message). The transaction's `manifest.json` is updated to `status: partial` either way -- it is never silently marked as fully rolled back if it wasn't. Fix the underlying issue (e.g., a service that won't start) and re-run `auditforge rollback <same id>`; rollback re-attempts every item in the transaction each time it's invoked, so re-running is safe (each primitive's `rollback()` is expected to be idempotent, matching the `apply()` idempotency requirement).
