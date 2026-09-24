# Contributing to AuditForge

## Before you start

Read `docs/ARCHITECTURE.md`. The core rule that shapes everything else: **control YAML files never contain code.** A control declares which primitive to use and what parameters to pass; only reviewed, tested Python in `controls/<os>/primitives.py` ever touches the real system.

## Adding or changing a control

See `docs/CONTROLS.md`, "Adding a new control." In short: if an existing primitive covers your case, it's a YAML-only change; run `pytest tests/unit/test_control_loader.py` to validate schema and primitive references before opening a PR.

Every control needs:
- A `rationale` written in your own words -- never copied from a benchmark's descriptive text. See `docs/SOURCES.md`'s CIS licensing note for why this matters specifically, and treat it as the policy for every framework, not just CIS.
- An honest `severity`. Remember severity controls FAIL-vs-WARNING (`docs/CONTROLS.md`) -- don't mark something `high`/`critical` just to make it visible; use `low`/`info` for genuinely contextual "review this" findings, matching the project's anti-false-positive philosophy (section 34 of the original project brief, and see how the existing RDP/WinRM/SMB-exposure controls handle this).
- A real `external_reference` you can trace to an actual document. If you're not sure a citation is current, say so in the `notes` field rather than guessing -- see how `docs/SOURCES.md` records "could not verify" caveats explicitly instead of smoothing them over.

## Adding a new primitive

1. Add a class to the relevant `controls/<os>/primitives.py`, subclassing `Primitive` (`core/registry.py`), decorated with `@register`.
2. Implement `probe()`. It must never modify the system.
3. If it should be remediable, implement `apply()` and `rollback()`. Both must be idempotent -- running them twice must not progressively change or break anything (see `docs/ROLLBACK.md` and the idempotency tests in `tests/unit/test_engine.py`/`test_linux_primitives.py` for the expected pattern).
4. Validate every parameter that will be interpolated into a subprocess argv element or generated script/config text with `utils.safe_exec.validate_token()`, even though control YAML is a trusted source today -- this is defense in depth per `docs/ARCHITECTURE.md`'s threat model, and it's the existing convention throughout the codebase.
5. Write a unit test using mocked OS state (fake in-memory `winreg` for Windows, monkeypatched `run`/paths for Linux/macOS) -- see `tests/unit/test_windows_primitives.py` and `tests/unit/test_linux_primitives.py` for the pattern. Real-system testing (Docker for Linux, a real machine for Windows) is valuable too if you have it, but the unit tests are what CI runs.

## Safety rules that are not negotiable in a PR

See `docs/HARDENING.md`, "What harden will never do." Do not add a remediation path for disk encryption, SIP, Gatekeeper's on/off switch, or sudoers editing. Do not remove the RDP/SSH connectivity guards. Do not make a high-impact control's `high_impact: true` flag optional or default-bypassed.

## Running the test suite

```
pip install -e ".[dev]"
pytest tests/ -v
ruff check auditforge tests
```

The suite is designed to run without any real Windows/Linux/macOS system underneath it (mocked OS state throughout) -- if your change requires real-system testing to verify, say so in the PR description and describe what you actually ran it against (see `docs/TEST_MATRIX.md`'s format for how this project records that distinction).

## Code style

- No comments explaining *what* code does; only *why*, when it's non-obvious (a workaround, a subtle invariant, a hidden constraint). Match the existing docstrings' tone.
- `ruff check` must pass with this repo's pinned rule set (`pyproject.toml`, `[tool.ruff.lint] select`).
