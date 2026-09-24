# AuditForge Architecture

## Design goals, in priority order

Matching the project's stated hardening philosophy: secure, reversible, explainable, evidence-based, compatible, auditable, maintainable.

The single architectural decision that flows from this is: **control YAML files never contain code.** A control declares *which* primitive to use and *what parameters* to pass it; the primitive itself is reviewed, versioned engine code. This means:

- A corrupted, malicious, or simply buggy control file cannot make AuditForge execute an arbitrary command -- it can only invoke one of a small, fixed set of primitives with the parameters that primitive expects.
- Adding a new control is a documentation-and-data exercise (write a YAML file), not a code change, once the primitive it needs already exists.
- Every primitive is independently testable (see `tests/unit/test_windows_primitives.py` and `tests/unit/test_linux_primitives.py` for the mocking pattern) without needing the real OS underneath it.

## Layers

```
controls/<os>/*.yml          <- declarative: "use primitive X with params Y, expect Z"
controls/<os>/primitives.py  <- the only code that touches the real OS
core/control_loader.py       <- loads + JSON-schema-validates the YAML above
core/registry.py             <- Primitive base class, ProbeResult/ApplyOutcome, compare_value()
core/engine.py                <- evaluate_control / run_audit / plan_harden / apply_harden
core/environment.py           <- OS/version detection, "is this centrally managed" detection
core/profile_loader.py        <- profiles/*.yml -> which controls run, what's allowed
rollback/transaction.py       <- transaction persistence (manifest.json per run)
rollback/executor.py           <- replays a transaction's ChangeRecords in reverse
reporting/generator.py         <- same AuditReport data -> JSON/CSV/Markdown/HTML
cli.py                          <- argparse subcommands + interactive menu
```

## The Primitive contract

Every primitive (`auditforge/core/registry.py:Primitive`) implements:

```python
def probe(self, params: dict) -> ProbeResult:      # required; must never modify the system
def apply(self, params: dict, expected_value) -> ApplyOutcome:  # optional; raises NotImplementedError by default
def rollback(self, params: dict, change: ChangeRecord) -> bool: # optional; raises NotImplementedError by default
def compare(self, detected, expected) -> bool:      # optional override; defaults to compare_value()
```

A control YAML with no `remediation:` block is audit-only -- the engine never calls `apply()` for it, and `ControlDefinition.remediation_available` is `False`. This is how FileVault/SIP/Gatekeeper/BitLocker/Secure-Boot/Credential-Guard/SUID-inventory/sudoers-scan/local-admin-membership are all made structurally incapable of being auto-remediated, regardless of CLI flags -- there is no code path that could do it, not just a policy choice that happens to say no.

`compare_value()` (`core/registry.py`) implements a small expected-value mini-language beyond plain equality:

```yaml
expected_value: 1                       # equality
expected_value: {"min": 15}             # >=
expected_value: {"max": 10}             # <=
expected_value: {"min": 1, "max": 10}   # range
expected_value: {"one_of": ["a", "b"]}  # set membership
expected_value: {"not": "Disabled"}     # inequality
```

## Status decision logic (`core/engine.py:evaluate_control`)

1. Primitive lookup fails, or `probe()` raises -> `ERROR`.
2. `ProbeResult.not_applicable` -> `NOT_APPLICABLE` (e.g. a feature that doesn't exist on this SKU, a file that doesn't exist, a tool that isn't installed).
3. `ProbeResult.manual_review` -> `MANUAL_REVIEW` (e.g. local-admin-group membership, SUID inventory, sudoers NOPASSWD scan -- findings where the primitive can gather the facts but a pass/fail judgment requires human context).
4. Control has `management_detection: true` AND the primitive's evidence includes `raw["policy_source"]` (currently only set for Windows registry values under `SOFTWARE\Policies\...`, a Microsoft convention that GPO/MDM use) -> `MANAGED_BY_ORGANIZATION`.
5. Otherwise, `primitive.compare(detected, expected)`. On match -> `PASS`. On mismatch, severity `medium`/`high`/`critical` -> `FAIL`; severity `low`/`info` -> `WARNING`.

**Known limitation:** the `MANAGED_BY_ORGANIZATION` policy-source heuristic only works for the subset of Windows settings that live under a `SOFTWARE\Policies\` registry key -- many GPO-controlled settings (LSA/Lsa key values, secedit-based local security policy) write directly to the same location a local admin would, with no structural signal distinguishing "a GPO set this" from "an admin set this by hand." Those controls' YAML notes fields say so explicitly rather than claim detection that doesn't exist. Linux/macOS have no `MANAGED_BY_ORGANIZATION` detection at all yet (roadmap item) -- `ManagementInfo.managed`/`.sources` are still computed and shown in every report (domain join / Ubuntu Pro / config-management-tool presence / MDM enrollment), just not wired into per-control status.

## Transactions and rollback

Every `harden` run gets a transaction ID (`AF-YYYYMMDD-HHMMSS-XXXXXX`) and a manifest under `state_dir()/transactions/<id>/manifest.json` (state dir resolution: `%ProgramData%\AuditForge` / `/var/lib/auditforge` if writable, else a per-user fallback -- see `rollback/transaction.py:_default_state_root`). Each applied control appends a `ChangeRecord` (control ID, primitive name, params, previous value, new value, timestamp) to that manifest -- **never** a secret; every primitive AuditForge ships only ever reads/writes configuration state, never credential material.

`rollback/executor.py:rollback_transaction` replays a transaction's changes in **reverse order**, calling each primitive's `rollback()` with the recorded `previous_value`. Rollback is best-effort per item -- one failed item is recorded and reported but does not stop the rest from being attempted, and the transaction's final status (`rolled_back` vs `partial`) reflects whether every item actually restored.

Primitives that manage config through a dedicated drop-in file they own outright (`/etc/sysctl.d/90-auditforge.conf`, `/etc/ssh/sshd_config.d/00-auditforge.conf`, `/etc/systemd/journald.conf.d/90-auditforge.conf`) make rollback exact and side-effect-free: removing AuditForge's own line/file reverts to whatever the rest of the system's configuration already specified, without AuditForge ever having edited a file it doesn't own. Primitives that must edit a single-purpose file directly (`/etc/login.defs`, `pwquality.conf`, `faillock.conf`) do so by replacing exactly one line and preserving everything else byte-for-byte otherwise.

## Why `secedit`-based Windows policy uses export-modify-reapply, not a partial `/configure`

`auditforge/controls/windows/primitives.py:_secedit_apply` exports the **entire** current `SECURITYPOLICY` area, patches the one line for the setting being changed, and reapplies the entire modified export. A naive script that hand-writes a small `.inf` with only the one setting it cares about and calls `secedit /configure` with it will *reset every other unspecified security-policy setting on that area to the template's defaults* -- a well-known footgun. Exporting first avoids it.

## Threat model / security review of AuditForge itself

See section 32 of the original project brief for the full list; concretely, in this codebase:

- **No `shell=True`, ever.** `utils/safe_exec.py:run()` always passes an argv list to `subprocess.run`.
- **No PowerShell `-Command` string interpolation.** `run_powershell()` pipes the script on stdin; control-file text can never break out of the script via `$()`/backtick/quote injection against the *invocation* itself (it can still affect the script's own logic if a property name were somehow malicious, which is why every property/key name is still passed through `validate_token()` before being interpolated into the generated script text -- defense in depth, not the primary control).
- **`validate_token()`** is a cheap allowlist regex check applied to every value that will be interpolated into an argv element or generated script/config text, even though those values come from AuditForge's own trusted YAML. It has no whitespace in its default pattern (newlines specifically, since a value later written into a generated config file could otherwise inject a new line); callers that need spaces (Windows registry paths with spaces like `Terminal Server`, audit-policy subcategory names like `Process Creation`) pass an explicit, narrower pattern.
- **Binaries are resolved to known-good absolute paths first** (`_KNOWN_PATHS` in `safe_exec.py` -- System32, `/usr/sbin`, `/usr/bin`, ...) before falling back to a `PATH` lookup, to reduce PATH-hijacking risk.
- **Every subprocess call has a timeout.** Nothing can block the engine forever.
- **No secrets are ever recorded.** Enforced by construction (every primitive only reads/writes configuration state) and spot-checked by `tests/unit/test_transaction.py::test_no_secrets_ever_recorded_in_change_record`.
- **Temp files use `tempfile.mkdtemp`** (owner-only by default) for the `secedit` export/apply workflow, and are removed in a `finally` block.
- Report HTML is rendered through Jinja2's `autoescape=True` (`reporting/generator.py:render_html`), so control titles/messages/evidence values can never inject markup into the report even though they ultimately originate from YAML files that ship with the product (defense in depth again -- this data is trusted today, but the renderer doesn't assume it always will be).

## Known limitations (see also docs/TEST_MATRIX.md and docs/CONTROLS.md)

- Profiles and frameworks metadata are loaded relative to the package's parent directory (`core/paths.py`), which assumes a source checkout or editable install. A plain, non-editable `pip install auditforge` would not find them -- packaging this properly is a roadmap item.
- No PDF report generation (spec section 16 lists it as optional; not implemented).
- No Ubuntu Security Guide (USG) integration (spec section 8; not implemented).
- No SCAP/STIG machine-readable content ingestion (spec section 2; DISA STIGs are referenced by document/version only, not per-control Vuln-ID/Rule-ID, to avoid fabricating IDs that were never verified against the actual XCCDF content).
- The Windows RDP-session connectivity guard checks `SESSIONNAME`; there is no equivalent guard implemented yet for a WinRM-based remote session, or for macOS SSH sessions (both noted in the affected controls' YAML).
