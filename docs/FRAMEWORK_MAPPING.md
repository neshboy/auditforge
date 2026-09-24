# Framework Mapping

AuditForge maps its own controls to external frameworks by **control ID reference**, never by reproducing the framework's own descriptive/rationale text -- see the CIS licensing note below, which is the specific reason this rule exists.

## What's actually populated today

| Framework | Populated in control YAML? | Where the authoritative data lives |
|---|---|---|
| NIST SP 800-53 (control families: AC, IA, AU, SC, SI, CM, ...) | **Yes**, on most controls, e.g. `nist_800_53: ["AC-2", "IA-5"]` | `docs/SOURCES.md` (NIST section); family-level, not tailored to a specific baseline (Low/Moderate/High) |
| NIST SP 800-63B-4 | **Yes**, specifically on password-policy controls (`AF-WIN-ACCT-006/007/008`, `AF-LNX-AUTH-001/003`) | `docs/SOURCES.md` -- verified by direct read of the SP 800-63B-4 PDF, Sec. 3.1.1.1-3.1.1.2 |
| Microsoft Security Baseline | Referenced via the `benchmark`/`benchmark_version`/`external_reference` fields on most Windows controls, but not (yet) via a structured `frameworks.microsoft_baseline` list of specific baseline setting IDs | `docs/SOURCES.md` (Microsoft section) -- current baseline versions and dates were live-verified |
| Apple Platform Security / Deployment | Referenced the same way on macOS controls | `docs/SOURCES.md` (Apple section) |
| DISA STIG | **Document/version level only** (`frameworks/disa.yml`) -- current STIG versions and release dates for Windows 11/Server 2022/Server 2025/Ubuntu 22.04+24.04/RHEL 8+9/macOS 26+15 were live-verified against `dl.dod.cyber.mil` | **Not** mapped per-control to specific Vuln-ID/Rule-ID values. See "Why DISA per-control IDs are not included" below. |
| CIS Benchmarks | **Not referenced by ID at all yet** in any control YAML (roadmap item) | `docs/SOURCES.md` (CIS section) records the licensing terms so this can be done correctly when it is |

## Why DISA per-control IDs are not included

Mapping `AF-WIN-SMB-001` to, say, `WN11-SO-000005` (a specific STIG Vuln-ID) requires actually parsing the STIG's XCCDF/SCAP content and confirming the rule IDs are current for the exact STIG version referenced. That parsing was not done in this project -- `docs/SOURCES.md`'s DISA section confirms the STIG *documents themselves* (version, release date, download URL) via live checks against `dl.dod.cyber.mil`, but the research explicitly could not retrieve or verify individual Vuln-ID/Rule-ID content (the STIG viewer pages rendered as an empty JS shell to the research tooling). Inventing plausible-looking STIG IDs from training-data memory would risk citing IDs that don't exist, are stale, or don't match the specific STIG revision listed -- exactly the kind of fabrication this project's own instructions rule out. This is recorded here as an explicit roadmap item, not silently skipped.

## CIS licensing (read before adding any CIS reference)

Per `docs/SOURCES.md`: CIS Benchmark PDFs are licensed CC BY-NC-SA 4.0, but CIS's own Terms of Use layer additional contractual restrictions on top of that license for non-SecureSuite-members -- specifically, **no rehosting the PDF elsewhere**, and **no derivative work "based directly on" a Benchmark**. AuditForge's policy, applied consistently across every control file in this repo: reference CIS content **by control ID only** (e.g., "CIS Benchmark for Ubuntu 22.04 LTS, control 1.1.1.1"), and never copy CIS's descriptive or rationale text. Every `rationale:` field in every control YAML in this repo is written in AuditForge's own words, independently of any benchmark's phrasing, for exactly this reason -- not just for CIS, but as a consistent policy for every framework referenced.

## `auditforge framework status`

Reads `frameworks/*.yml` and prints each publication's current known status (`CURRENT` / `UPDATE_AVAILABLE`) as of the `last_verified` date in that file. This does **not** phone home or fetch anything live -- it reflects the state recorded the last time someone (a human or an AI agent doing live research, as happened during this project's development) actually checked the authoritative source and updated the YAML. Treat a long-unrefreshed `last_verified` date as a sign the framework files need a fresh research pass, not as an active monitoring feature.
