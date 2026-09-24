# AuditForge Test Matrix

This document records what was **actually run**, where, and with what result. Nothing here is marked PASS unless it was actually executed and observed; anything not executed is marked `NOT TESTED`. See `docs/SOURCES.md` for the authoritative-guidance research behind the controls themselves.

Last updated: 2026-09-24, during initial v0.1.0 development.

## Automated test suite

| Suite | Where it ran | Result |
|---|---|---|
| `pytest tests/` (99 tests) | Native Windows 11 (Python 3.12, this dev machine) | 96 passed, 3 skipped (POSIX-permission-bit tests correctly skip on NTFS) |
| `pytest tests/` (99 tests) | Disposable, privileged Ubuntu 24.04 Docker container, real systemd as PID 1 | 99 passed, 0 skipped |
| `ruff check auditforge tests` | Native Windows | All checks passed (E/F/I rule set -- see `pyproject.toml`) |
| ShellCheck on `scripts/linux/auditforge.sh`, `scripts/macos/auditforge.sh` | Ubuntu 24.04 Docker container | 0 issues |
| PowerShell parse of `Run-AuditForge.ps1` | Native Windows PowerShell (`[ScriptBlock]::Create`, parse-only, no execution) | Parses cleanly |
| CI workflow (`.github/workflows/ci.yml`) | GitHub Actions | **NOT TESTED** -- the workflow file is written and the equivalent commands were run locally as above, but the workflow itself has not yet executed on GitHub's runners (this requires the repository to actually be pushed; see the project's final report for status) |

## Windows

| Item | Method | Result |
|---|---|---|
| Environment/management detection | Live, this machine (Windows 11 Enterprise N, build 26200, 25H2) | Works; reports `managed=False` correctly (not domain/Intune-joined) |
| Full audit run, all 62 Windows controls | Live, this machine, read-only `auditforge audit` | Completed in ~67s. Real result: 30 PASS / 14 FAIL / 7 WARNING / 1 MANUAL_REVIEW / 8 MANAGED_BY_ORGANIZATION / 1 NOT_APPLICABLE / 1 ERROR, score 58.8% |
| HTML/JSON/CSV/Markdown report generation | Live, this machine | All four formats generated and spot-checked (no unrendered template syntax, expected-value formatting correct, category meters render with real percentages) |
| `harden` (real remediation applied to this machine) | **NOT RUN** | Per this project's explicit safety agreement for this session, no hardening was applied to the real development machine -- see the Limitations section of the final project report |
| `harden`/`rollback`/`verify` logic | Unit tests with a fake in-memory `winreg` (mocked OS state) | Passing -- see `tests/unit/test_windows_primitives.py` (probe/apply/rollback round-trip, idempotency, absent-value sentinel handling, RDP connectivity guard) |
| Bugs found by testing | -- | `@register` decorator storing a class instead of an instance (would have broken every single Windows/Linux/macOS primitive at runtime); `ConvertTo-Json` serializing Service `StartType`/`Status` and BitLocker `ProtectionStatus` enums as raw integers instead of names; `AF-WIN-SMB-003` referencing the wrong SMB cmdlet's property (`EnableInsecureGuestLogons` is a client-config property, not server-config); `RunAsPPL=2` (UEFI-locked) wrongly failing a control that only accepted `1`; a stale "14 characters" password-length baseline corrected to NIST SP 800-63B-4's verified 15-character minimum. All fixed; see git history. |
| Windows Server 2022/2025 | **NOT TESTED** -- no such machine/VM was available in this environment |
| Older Windows (Server 2019 and earlier) | **NOT TESTED**; not a target platform for v0.1 |

## Linux

| Item | Method | Result |
|---|---|---|
| Environment/management detection | Live, disposable Ubuntu 24.04 Docker container (`--privileged`, real systemd as PID 1, source mounted in) | Works |
| Full audit run, all 41 Linux controls | Live, container | Completed in ~5.6s. Real result: 19 PASS / 5 FAIL / 7 WARNING / 8 NOT_APPLICABLE / 2 MANUAL_REVIEW / 0 MANAGED_BY_ORGANIZATION / 0 ERROR, score 61.3% |
| Full harden -> transaction -> post-audit -> rollback -> post-rollback pipeline | Live, container, against 4 real controls (`AF-LNX-KRN-008`, `AF-LNX-SSH-004`, `AF-LNX-SSH-005`, `AF-LNX-SVC-008`) | All 4 applied successfully, post-audit confirmed PASS on all 4, rollback restored all 4 to their exact original values, verified by a second audit |
| Idempotency (apply the same change 3x in a row) | Live, container, `linux_sshd_option` and `linux_sysctl` | Confirmed idempotent -- repeated application does not change the outcome or error |
| Bugs found by testing | -- | `sshd -t` failing with "Missing privilege separation directory: /run/sshd" when sshd had been stopped by an unrelated test just before -- fixed by having the primitive ensure `/run/sshd` exists before validating, since that directory is normally created by the service manager, not by `sshd -t` itself; `PermitRootLogin`'s `without-password` legacy alias for `prohibit-password` not being accepted by `AF-LNX-SSH-001`. Both fixed. |
| Ubuntu 22.04 | Same primitives, not independently re-run on a 22.04 container | **NOT TESTED** directly, but the primitives used (`sysctl`, `sshd -T`, `systemctl`, plain file I/O) are not 24.04-specific |
| Debian 12/13 | -- | **NOT TESTED** -- no Debian container was built in this session |
| RHEL / Rocky / AlmaLinux | -- | **NOT TESTED** -- no RHEL-family container was built; `linux_faillock`/`linux_firewalld_status`/RHEL-scoped controls (`AF-LNX-AUTH-004`, `AF-LNX-SVC-009`) are UNTESTED beyond unit-level mocks |
| Ubuntu Security Guide (USG) integration | -- | **NOT IMPLEMENTED** -- section 8 of the project spec calls for optional USG integration; this is a roadmap item, not built in v0.1 |

## macOS

| Item | Method | Result |
|---|---|---|
| Everything | -- | **NOT TESTED.** No Apple hardware or macOS VM was available in this development environment. The macOS module (9 primitives, 15 controls) was written from documented `defaults`/CLI behavior and cross-referenced against live-researched Apple documentation (`docs/SOURCES.md`), but has never actually been executed against a real or virtualized Mac. |
| Design-level safety review | Manual code review | FileVault, SIP, and Gatekeeper are audit-only by construction (no `apply()`/`rollback()` path exists for them at all -- see `docs/CONTROLS.md`), so even a currently-undiscovered bug in those specific primitives cannot cause AuditForge to change encryption, integrity protection, or Gatekeeper state on a real Mac. |

**Do not run `auditforge harden` against a real Mac using this release without independently verifying every macOS primitive first.** Treat the entire macOS module as a well-intentioned draft pending real-hardware validation, not a production-ready feature.

## What "verified" means in this document

- **Live**: the actual code path executed against a real OS (this Windows machine, or a real Linux kernel/systemd in a container) and the observed output is what's recorded above.
- **Unit tests with mocked OS state**: the primitive's logic was exercised with a fake in-memory registry / monkeypatched subprocess calls / tmp-path config files, which validates the Python-level logic (parsing, comparison, idempotency, rollback bookkeeping) but does NOT prove the underlying OS command/API behaves as assumed on a real system.
- **NOT TESTED**: exactly what it says. No code path was executed. Do not treat as working.
