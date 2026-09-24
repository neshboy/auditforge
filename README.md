# AuditForge

**Cross-platform endpoint security audit and safe hardening framework for Windows, Linux, and macOS.**

> **Status: v0.1.0, actively developed.** Windows and Linux are genuinely tested (see below). macOS is written but **not yet validated on real Apple hardware** -- read `docs/TEST_MATRIX.md` before trusting it with anything. This is not a finished, audited-by-a-third-party product; it's a real, working first release.

![AuditForge terminal demo](docs/assets/demo.svg)

```
Scan -> Audit -> Explain -> Backup -> Harden -> Verify -> Report -> Roll Back
```

**[-> See it in action: real report screenshots, real GitHub CI, real rollback pipeline (docs/SHOWCASE.md)](docs/SHOWCASE.md)**

## What this is

One command tells you where a Windows, Linux, or macOS machine stands against current security guidance -- PASS, FAIL, WARNING, NOT_APPLICABLE, MANUAL_REVIEW, or MANAGED_BY_ORGANIZATION, per control, with evidence, a citation, and (where it's safe and reversible) an optional one-command fix. Every change AuditForge makes gets a transaction ID and can be rolled back.

It is **not** a collection of "disable everything" scripts. It does not blindly kill SMB, force password rotation, or treat every open port as malicious -- see "Safety philosophy" below. It follows current authoritative guidance (NIST SP 800-53/800-63B-4, DISA STIGs, Microsoft Security Baselines, Apple Platform Security), live-researched and cited in `docs/SOURCES.md`, not decade-old hardening folklore.

## Supported platforms

| OS | Controls | Status |
|---|---|---|
| Windows 11, Server 2022, Server 2025 | 62 | Live-tested (audit) on a real Windows 11 machine; harden/rollback logic unit-tested with mocked registry state |
| Ubuntu 22.04/24.04, Debian 12/13, RHEL/Rocky/AlmaLinux | 41 | Live-tested (audit **and** full harden/rollback) in a real Ubuntu 24.04 container; RHEL-family and Debian controls are logic-tested but not independently container-verified |
| macOS (currently maintained versions) | 15 | Written and researched, **not tested on real hardware** -- no Mac was available in this project's development environment |

See `docs/TEST_MATRIX.md` for the exact, honest breakdown of what ran where.

## Quick start

```bash
# Windows (PowerShell, run elevated for full results)
scripts\windows\Run-AuditForge.ps1 audit

# Linux / macOS
sudo ./scripts/linux/auditforge.sh audit      # or scripts/macos/auditforge.sh
```

First run bootstraps a local Python virtualenv and installs AuditForge in editable mode automatically. Run with no arguments for the interactive menu:

```
========================================
AUDITFORGE
Endpoint Security Audit & Hardening
========================================

[1] Run Security Audit
[2] Preview Hardening (dry run)
[3] Apply Recommended Hardening
[4] Apply Strict Hardening
[5] Generate Report
[6] Verify Previous Hardening
[7] Roll Back Previous Changes
[8] Advanced Options (profiles / framework status)
[9] Exit
```

### Audit only (always safe, always read-only)

```bash
auditforge audit --profile audit_only --format html,json,csv,markdown
```

Nothing is ever changed by `audit` -- there is no code path in the audit command that calls a primitive's `apply()`. See `docs/ARCHITECTURE.md`.

### Preview hardening (still nothing changes)

```bash
auditforge harden --profile workstation --dry-run
```

### Apply hardening

```bash
auditforge harden --profile workstation          # prompts for confirmation
auditforge harden --profile strict --allow-high-impact --yes   # for scripted/CI use
```

**Read `docs/HARDENING.md` first.** Run `audit` and `--dry-run` before this, every time, especially on a machine you didn't set up yourself.

### Rollback

```bash
auditforge rollback --list
auditforge rollback AF-20260924-153533-A7F21C
```

### Verify (detect drift since a previous harden run)

```bash
auditforge verify
```

### Framework/benchmark status

```bash
auditforge framework status
auditforge profiles
```

See `examples/cli-transcripts.md` for real, captured session output (not mockups), and `examples/sample-audit-report.html` for a real generated report from this project's own development machine.

## Safety philosophy

Priority order: **secure, reversible, explainable, evidence-based, compatible, auditable, maintainable.** Concretely, `harden` (regardless of profile or flags) will never:

- Enable disk encryption (BitLocker/FileVault) without an existing recovery-key plan.
- Change System Integrity Protection or Gatekeeper's on/off switch.
- Edit `/etc/sudoers` or `/etc/sudoers.d/*` in any way.
- Disable RDP while connected via RDP, or SSH while connected via SSH (Windows/Linux; see `docs/CONTROLS.md` for the current gaps in this guard on WinRM/macOS SSH).
- Reduce local Administrators/sudo group membership.
- Flush or replace existing firewall rules -- ufw/firewalld are only ever *enabled*, never disabled; nftables/iptables rules are never touched at all.
- Install, uninstall, or upgrade any package.
- Force password complexity rules or mandatory rotation -- current NIST SP 800-63B-4 guidance (verified July 2025) explicitly recommends against both; see `docs/FAQ.md`.

Every one of these is enforced structurally (no `apply()` path exists at all for the audit-only controls) rather than by a runtime check that could have a bug in it -- see `docs/ARCHITECTURE.md`.

**Hardening can break things.** A password-length increase can lock out an account with a shorter existing password until next reset; disabling SMBv1 can break a legacy NAS; enabling `PasswordAuthentication no` before every admin has a working SSH key will lock out password-only accounts. Every control's `possible_impact` field says what to check first. Always `--dry-run`.

## Architecture, in one paragraph

Control YAML files never contain code -- they declare *which* trusted, reviewed "primitive" to use (`win_registry_dword`, `linux_sysctl`, `macos_defaults`, ...) and what parameters to pass it, plus the expected value, severity, citation, and rollback/impact metadata. Only the primitives themselves (`auditforge/controls/<os>/primitives.py`) ever call a real OS API or shell out to a real tool, always via argv lists (never `shell=True`), always with an allowlist check on any interpolated value. Full detail, including this project's own threat model, in `docs/ARCHITECTURE.md`.

```
auditforge/
├── core/            OS detection, engine, control loader, transaction/rollback storage
├── controls/        <os>/*.yml (declarative controls) + <os>/primitives.py (the only code that touches the OS)
├── reporting/        JSON/CSV/Markdown/HTML generation
├── rollback/         transaction persistence + rollback executor
└── cli.py           audit / harden / rollback / verify / framework / profiles + interactive menu

profiles/            workstation, corporate, developer, server, public_server, strict, audit_only
frameworks/          NIST/DISA/Microsoft/Apple metadata, live-verified (docs/SOURCES.md)
scripts/             one-click launchers per OS
docs/                architecture, control reference, hardening/rollback guides, framework mapping, test matrix, FAQ, sources
tests/               99 unit tests, mocked-OS-state where a real system isn't required
```

## Frameworks referenced

NIST SP 800-53, SP 800-63B-4, CSF 2.0 (family/control-ID level); Microsoft Security Baselines (Windows 11 25H2, Server 2022, Server 2025); Apple Platform Security/Deployment guides; DISA STIGs (document/version level -- see `docs/FRAMEWORK_MAPPING.md` for why per-control Vuln-ID mapping isn't included yet). CIS Benchmarks are referenced by their published licensing terms in `docs/SOURCES.md`, and this project's policy of citing CIS content **by control ID only, never by reproducing benchmark text** is documented there and followed in every control file -- no per-control CIS mapping exists yet. Full detail and live-verified publication dates/versions: `docs/SOURCES.md` and `docs/FRAMEWORK_MAPPING.md`.

## Limitations (read this)

- **macOS is untested on real hardware.** See `docs/TEST_MATRIX.md`. Do not run `harden` against a production Mac based on this release alone.
- No PDF reports, no Ubuntu Security Guide (USG) integration, no SCAP/STIG machine-readable content ingestion, no per-control CIS/DISA-Vuln-ID mapping. All documented as explicit roadmap items, not silently skipped -- see `docs/ARCHITECTURE.md` and `docs/FRAMEWORK_MAPPING.md`.
- `MANAGED_BY_ORGANIZATION` detection only works for Windows registry values under a `SOFTWARE\Policies\` key combined with a domain/MDM signal; it is not implemented for Linux/macOS, and even on Windows it can't distinguish "a GPO set this" from "an admin set this by hand" for settings that live outside that registry convention (secedit-based policy, LSA key values). See `docs/ARCHITECTURE.md`.
- RHEL/Rocky/AlmaLinux- and Debian-specific controls are logic-tested (mocked) but were not independently verified in a container of those distributions specifically.
- Profiles/frameworks metadata assumes a source checkout, not a packaged `pip install`.

## Roadmap

Ubuntu Security Guide integration, per-control CIS/DISA ID mapping (pending someone actually parsing the SCAP/XCCDF content rather than guessing IDs), a WinRM/macOS-SSH connectivity guard, real macOS hardware validation, PDF reports, expanding beyond the current ~30-60 controls per OS toward fuller CIS/STIG coverage.

## License

MIT -- see `LICENSE`. AuditForge's own text (control rationale, documentation) is original; it references CIS/DISA/NIST/Microsoft/Apple guidance by citation, never by reproducing their protected text -- see `docs/SOURCES.md`.

## Contributing

See `CONTRIBUTING.md`. Security issues: see `SECURITY.md`, not a public issue.
