"""The audit/harden orchestration engine. This module contains no OS-specific
logic at all -- it only knows how to walk a list of ControlDefinitions,
call the primitive each one names, and turn the result into a ControlResult.
All Windows/Linux/macOS specifics live in controls/<os>/primitives.py.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Optional

from auditforge.core import registry
from auditforge.core.environment import EnvironmentInfo, ManagementInfo
from auditforge.core.models import ChangeRecord, ControlDefinition, ControlResult, Evidence, Severity, Status
from auditforge.rollback.transaction import Transaction, TransactionManager


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evaluate_control(control: ControlDefinition, management: ManagementInfo) -> ControlResult:
    primitive_name = control.audit["primitive"]
    try:
        primitive = registry.get(primitive_name)
    except KeyError as exc:
        evidence = Evidence(None, control.expected_value, primitive_name, _now())
        return ControlResult(control, Status.ERROR, evidence, message=str(exc), error=str(exc))

    try:
        probe = primitive.probe(control.audit.get("params", {}))
    except Exception as exc:  # noqa: BLE001 - a probe must never crash the whole audit
        evidence = Evidence(None, control.expected_value, primitive_name, _now())
        return ControlResult(control, Status.ERROR, evidence, message=f"probe failed: {exc}", error=str(exc))

    evidence = Evidence(probe.value, control.expected_value, probe.source or primitive_name, _now(), probe.raw)

    if probe.error:
        return ControlResult(control, Status.ERROR, evidence, message=probe.error, error=probe.error)
    if probe.not_applicable:
        return ControlResult(control, Status.NOT_APPLICABLE, evidence, message=probe.not_applicable_reason)
    if probe.manual_review:
        return ControlResult(control, Status.MANUAL_REVIEW, evidence, message=probe.manual_review_reason)

    policy_source = (probe.raw or {}).get("policy_source")
    if control.management_detection and policy_source:
        return ControlResult(
            control, Status.MANAGED_BY_ORGANIZATION, evidence, message=f"Managed via {policy_source}"
        )

    passed = primitive.compare(probe.value, control.expected_value)
    if passed:
        return ControlResult(control, Status.PASS, evidence, message="Compliant")

    status = Status.FAIL if control.severity.rank >= Severity.MEDIUM.rank else Status.WARNING
    return ControlResult(
        control,
        status,
        evidence,
        message=f"Expected {control.expected_value!r}, found {probe.value!r}",
    )


@dataclasses.dataclass
class AuditReport:
    environment: EnvironmentInfo
    management: ManagementInfo
    profile: str
    generated_at: str
    results: list  # list[ControlResult]

    def summary(self) -> dict:
        counts = {s.value: 0 for s in Status}
        by_category: dict = {}
        for r in self.results:
            counts[r.status.value] += 1
            cat = by_category.setdefault(
                r.control.category, {s.value: 0 for s in Status}
            )
            cat[r.status.value] += 1
        total_scored = sum(
            counts[s] for s in (Status.PASS.value, Status.FAIL.value, Status.WARNING.value)
        )
        passed = counts[Status.PASS.value]
        score = round(100 * passed / total_scored, 1) if total_scored else None
        return {
            "counts": counts,
            "by_category": by_category,
            "total_controls": len(self.results),
            "score_percent": score,
        }

    def to_dict(self) -> dict:
        return {
            "hostname": self.environment.hostname,
            "os": self.environment.os.value,
            "os_name": self.environment.os_name,
            "os_version": self.environment.os_version,
            "architecture": self.environment.architecture,
            "profile": self.profile,
            "generated_at": self.generated_at,
            "management": {
                "managed": self.management.managed,
                "sources": list(self.management.sources),
            },
            "summary": self.summary(),
            "results": [r.to_dict() for r in self.results],
        }


def run_audit(
    controls: list, environment: EnvironmentInfo, management: ManagementInfo, profile: str = "standard"
) -> AuditReport:
    results = [evaluate_control(c, management) for c in controls]
    return AuditReport(
        environment=environment, management=management, profile=profile, generated_at=_now(), results=results
    )


@dataclasses.dataclass
class PlannedChange:
    control: ControlDefinition
    current_result: ControlResult
    reason_skipped: Optional[str] = None


@dataclasses.dataclass
class HardenPlan:
    to_apply: list  # list[PlannedChange]
    skipped: list  # list[PlannedChange] with reason_skipped set

    def to_dict(self) -> dict:
        def item(p: PlannedChange) -> dict:
            return {
                "control_id": p.control.control_id,
                "title": p.control.title,
                "severity": p.control.severity.value,
                "current_value": p.current_result.evidence.detected_value,
                "expected_value": p.control.expected_value,
                "reboot_required": p.control.reboot_required,
                "service_restart_required": p.control.service_restart_required,
                "possible_impact": p.control.possible_impact,
                "reason_skipped": p.reason_skipped,
            }

        return {"to_apply": [item(p) for p in self.to_apply], "skipped": [item(p) for p in self.skipped]}


def plan_harden(
    controls: list,
    environment: EnvironmentInfo,
    management: ManagementInfo,
    allow_high_impact: bool = False,
) -> HardenPlan:
    to_apply, skipped = [], []
    for control in controls:
        result = evaluate_control(control, management)
        if result.status not in (Status.FAIL, Status.WARNING):
            continue
        if not control.remediation_available:
            skipped.append(PlannedChange(control, result, "no automated remediation (manual review only)"))
            continue
        if result.status == Status.MANAGED_BY_ORGANIZATION:
            skipped.append(PlannedChange(control, result, "managed by organization; not overriding policy"))
            continue
        if control.high_impact and not allow_high_impact:
            skipped.append(
                PlannedChange(control, result, "high-impact control requires --allow-high-impact")
            )
            continue
        to_apply.append(PlannedChange(control, result))
    return HardenPlan(to_apply=to_apply, skipped=skipped)


@dataclasses.dataclass
class ApplyResultItem:
    control_id: str
    outcome: str  # "applied" | "failed" | "verify_failed"
    message: str = ""


@dataclasses.dataclass
class HardenReport:
    tx: Transaction
    pre_audit: AuditReport
    post_audit: AuditReport
    applied: list  # list[ApplyResultItem]

    def to_dict(self) -> dict:
        return {
            "tx_id": self.tx.tx_id,
            "pre_audit": self.pre_audit.to_dict(),
            "post_audit": self.post_audit.to_dict(),
            "applied": [dataclasses.asdict(a) for a in self.applied],
        }


def apply_harden(
    plan: HardenPlan,
    all_controls: list,
    environment: EnvironmentInfo,
    management: ManagementInfo,
    profile: str,
    tx_manager: Optional[TransactionManager] = None,
) -> HardenReport:
    tx_manager = tx_manager or TransactionManager()
    tx = tx_manager.begin(profile=profile, os_name=environment.os.value, os_version=environment.os_version)

    pre_audit = run_audit(all_controls, environment, management, profile)
    tx.pre_audit_summary = pre_audit.summary()

    applied: list[ApplyResultItem] = []
    for planned in plan.to_apply:
        control = planned.control
        primitive_name = control.remediation["primitive"]
        try:
            primitive = registry.get(primitive_name)
            outcome = primitive.apply(control.remediation.get("params", {}), control.expected_value)
        except Exception as exc:  # noqa: BLE001 - one control's failure must not abort the run
            applied.append(ApplyResultItem(control.control_id, "failed", str(exc)))
            continue

        change = ChangeRecord(
            control_id=control.control_id,
            primitive=primitive_name,
            params=control.remediation.get("params", {}),
            previous_value=outcome.previous_value,
            new_value=outcome.new_value,
            timestamp=_now(),
            backup_file=outcome.backup_file,
        )
        tx_manager.record_change(tx, change)

        reprobe = evaluate_control(control, management)
        if reprobe.status == Status.PASS:
            applied.append(ApplyResultItem(control.control_id, "applied", outcome.notes))
        else:
            applied.append(
                ApplyResultItem(control.control_id, "verify_failed", f"post-apply status={reprobe.status.value}")
            )

    post_audit = run_audit(all_controls, environment, management, profile)
    failed = any(a.outcome != "applied" for a in applied)
    tx_manager.finalize(tx, "partial" if failed else "complete", post_audit.summary())

    return HardenReport(tx=tx, pre_audit=pre_audit, post_audit=post_audit, applied=applied)
