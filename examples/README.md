# Examples

`sample-audit-report.{html,json,md}` are **real, unmodified output** from `auditforge audit --profile audit_only` run against this project's own Windows 11 development machine on 2026-09-24 -- not mockups. Open `sample-audit-report.html` in a browser to see the actual dashboard AuditForge produces. The real score that run: 58.8% (30 PASS / 14 FAIL / 7 WARNING / 1 MANUAL_REVIEW / 8 MANAGED_BY_ORGANIZATION / 1 NOT_APPLICABLE / 1 ERROR out of 62 Windows controls).

See `docs/TEST_MATRIX.md` for exactly what was and wasn't verified, and `cli-transcripts.md` in this directory for real command-line session output (audit, dry-run harden, rollback) captured during development.
