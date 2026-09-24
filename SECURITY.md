# Security Policy

AuditForge runs with elevated/administrative privileges on every OS it supports, and its `harden` mode makes real configuration changes. Security issues in this project are taken seriously.

## Reporting a vulnerability

Please report suspected security vulnerabilities privately rather than opening a public issue. Open a GitHub Security Advisory ("Report a vulnerability" under the repository's Security tab) with:

- The affected OS/version and AuditForge version.
- Steps to reproduce, including the exact control ID or CLI command if applicable.
- What you observed vs. what you expected.
- Whether the issue could lead to privilege escalation, unintended system modification, credential exposure, or a bypass of one of the safety limits described in `docs/HARDENING.md` ("What harden will never do").

We aim to acknowledge reports within 5 business days.

## Scope

In scope:
- Command injection or unsafe subprocess usage in any primitive.
- A control or profile that could cause `harden` to disable SSH/RDP while the current session depends on it, edit sudoers, enable disk encryption without recovery planning, or otherwise violate a guarantee in `docs/HARDENING.md`.
- Path traversal, TOCTOU, or symlink issues in any file the engine reads/writes (control YAML, transaction manifests, generated reports, temp files used by `secedit`/similar).
- Secrets or credential material ending up in a transaction manifest, report, or log.
- HTML/script injection in a generated report.

Out of scope:
- Vulnerabilities in the underlying OS/tools AuditForge calls (report those to the vendor).
- Issues that require an attacker to already have local admin/root (AuditForge assumes it runs with that level of trust, same as the OS tools it wraps).

## This project's own threat model

See `docs/ARCHITECTURE.md`, "Threat model / security review of AuditForge itself," for the specific mitigations already in place (no `shell=True`, no PowerShell `-Command` string interpolation, `validate_token()` allowlisting, known-good absolute binary paths, subprocess timeouts, no secrets in transaction records, autoescaped HTML report rendering).
