# Changelog

All notable changes to AuditForge are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-09-24

Initial release.

### Added
- Core audit/harden/rollback/verify engine with a declarative primitive-registry architecture (`docs/ARCHITECTURE.md`).
- 62 Windows controls, 41 Linux controls, 15 macOS controls (118 total) across accounts, authentication, SSH, SMB, remote access, malware protection, firewall, kernel hardening, filesystem, services, logging, updates, boot integrity, and encryption (`docs/CONTROLS.md`).
- 24 Windows primitives, 17 Linux primitives, 9 macOS primitives.
- Transaction-based rollback (`docs/ROLLBACK.md`).
- 7 hardening profiles: `audit_only`, `workstation`, `corporate`, `developer`, `server`, `public_server`, `strict` (`docs/HARDENING.md`).
- HTML/JSON/CSV/Markdown report generation.
- CLI (`auditforge audit|harden|rollback|verify|framework|profiles`) plus an interactive menu.
- One-click launchers for Windows (PowerShell/cmd), Linux, and macOS.
- Live-researched source citations for NIST, DISA, Microsoft, and Apple guidance, current as of 2026-09-24 (`docs/SOURCES.md`), including correcting the password-length baseline to NIST SP 800-63B-4's verified 15-character minimum (superseding the older, still widely-cited SP 800-63B).
- 99-test automated suite (unit tests with mocked OS state; see `docs/TEST_MATRIX.md` for what was additionally verified live).
- CI: ruff lint, pytest matrix (ubuntu-latest/windows-latest x Python 3.10/3.12), ShellCheck, PSScriptAnalyzer, gitleaks secret scanning.

### Fixed (found via live/CI testing during development, before/around the initial release)
- `@register` storing the decorated class instead of an instance, which would have broken every single primitive at runtime.
- PowerShell's `ConvertTo-Json` serializing `Get-Service` `Status`/`StartType` and `Get-BitLockerVolume` `ProtectionStatus` as raw integers instead of names, causing false FAILs against string-based `expected_value`s.
- `AF-WIN-SMB-003` referencing `EnableInsecureGuestLogons` on the wrong SMB cmdlet (it's a client-config property, not server-config).
- `RunAsPPL=2` (UEFI-locked LSA protection, stronger than `1`) being wrongly flagged as non-compliant.
- Windows local password minimum length baseline corrected from a stale "14 characters" to NIST SP 800-63B-4's verified 15-character requirement.
- `sshd -t` (and, found separately via fresh-clone testing, `sshd -T`) failing with "Missing privilege separation directory: /run/sshd" whenever sshd was currently stopped -- both now share one helper that ensures the directory exists first.
- `AF-LNX-SSH-001` not accepting `without-password`, OpenSSH's legacy-name synonym for `prohibit-password`.
- `linux_sudoers_nopasswd_scan` crashing with an uncaught `PermissionError` on `os.listdir("/etc/sudoers.d")` when run as a non-root user -- the normal case for that directory's typical `0750 root:root` permissions, only missed locally because every Docker-based test had run as literal root.
- The `secret-scan` CI job failing outright on the repository's very first push (gitleaks-action's before/after diff range has no valid parent to diff from on a root commit) -- replaced with a direct full-history `gitleaks detect` scan.

### Known limitations (v0.1.0)
- macOS module is entirely untested on real Apple hardware -- no Mac was available during development. See `docs/TEST_MATRIX.md`.
- No PDF report generation.
- No Ubuntu Security Guide (USG) integration.
- DISA STIG references are at the document/version level only, not per-control Vuln-ID/Rule-ID (see `docs/FRAMEWORK_MAPPING.md` for why).
- No CIS Benchmark control-ID references yet (licensing terms are documented and ready in `docs/SOURCES.md`; the mapping work itself hasn't been done).
- `profiles/` and `frameworks/` are resolved relative to a source checkout, not packaged for a non-editable `pip install`.
- No WinRM-session or macOS-SSH-session connectivity guard (Windows RDP and Linux SSH have one; see `docs/CONTROLS.md`).
