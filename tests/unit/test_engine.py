import pytest

from auditforge.core.control_loader import load_control_file
from auditforge.core.engine import apply_harden, evaluate_control, plan_harden, run_audit
from auditforge.core.environment import EnvironmentInfo, ManagementInfo
from auditforge.core.models import OperatingSystem, Status
from auditforge.core.registry import ApplyOutcome, Primitive, ProbeResult, register
from auditforge.rollback.transaction import TransactionManager
import os

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


class _StubPrimitive(Primitive):
    """A controllable fake primitive: each test sets .next_value /
    .next_error / .next_manual_review / .next_na before calling probe."""

    name = "test_stub"

    def __init__(self):
        self.next_value = None
        self.next_error = None
        self.next_na = False
        self.next_manual_review = False
        self.applied = []
        self.rolled_back = []
        self.raise_on_apply = None

    def probe(self, params):
        return ProbeResult(
            value=self.next_value,
            error=self.next_error,
            not_applicable=self.next_na,
            manual_review=self.next_manual_review,
            raw=params.get("_raw", {}),
        )

    def apply(self, params, expected_value):
        if self.raise_on_apply:
            raise self.raise_on_apply
        self.applied.append((params, expected_value))
        previous = self.next_value
        self.next_value = params.get("value", expected_value)
        return ApplyOutcome(previous_value=previous, new_value=self.next_value)

    def rollback(self, params, change):
        self.rolled_back.append(change)
        self.next_value = change.previous_value
        return True


@pytest.fixture
def stub(isolated_registry):
    prim = _StubPrimitive()
    register(prim)
    return prim


@pytest.fixture
def env():
    return EnvironmentInfo(os=OperatingSystem.WINDOWS, os_name="TestOS", os_version="1.0", hostname="test-host")


@pytest.fixture
def unmanaged():
    return ManagementInfo(managed=False)


def _control(**overrides):
    c = load_control_file(os.path.join(FIXTURES, "valid_control.yml"))
    if overrides:
        c = c.__class__(**{**c.__dict__, **overrides})
    return c


def _stub_control(severity="medium", management_detection=False, remediation=None, high_impact=False):
    c = _control()
    return c.__class__(
        **{
            **c.__dict__,
            "audit": {"primitive": "test_stub", "params": {}},
            "remediation": remediation,
            "management_detection": management_detection,
            "high_impact": high_impact,
        }
    )


class TestEvaluateControl:
    def test_pass_when_value_matches(self, stub, unmanaged):
        stub.next_value = 1
        control = _stub_control()
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.PASS

    def test_fail_for_medium_or_above_severity_mismatch(self, stub, unmanaged):
        stub.next_value = 0
        control = _control()
        control = control.__class__(**{**control.__dict__, "audit": {"primitive": "test_stub", "params": {}}})
        assert control.severity.value == "medium"
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.FAIL

    def test_warning_for_low_severity_mismatch(self, stub, unmanaged):
        from auditforge.core.models import Severity

        stub.next_value = 0
        control = _control()
        control = control.__class__(
            **{**control.__dict__, "audit": {"primitive": "test_stub", "params": {}}, "severity": Severity.LOW}
        )
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.WARNING

    def test_not_applicable(self, stub, unmanaged):
        stub.next_na = True
        control = _stub_control()
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.NOT_APPLICABLE

    def test_manual_review(self, stub, unmanaged):
        stub.next_manual_review = True
        control = _stub_control()
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.MANUAL_REVIEW

    def test_error_on_probe_exception(self, stub, unmanaged):
        class _Boom(Primitive):
            name = "test_stub"

            def probe(self, params):
                raise RuntimeError("boom")

        from auditforge.core import registry

        registry._REGISTRY["test_stub"] = _Boom()
        control = _stub_control()
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.ERROR
        assert "boom" in result.error

    def test_unknown_primitive_is_error_not_crash(self, isolated_registry, unmanaged):
        control = _control()
        control = control.__class__(**{**control.__dict__, "audit": {"primitive": "nonexistent", "params": {}}})
        result = evaluate_control(control, unmanaged)
        assert result.status == Status.ERROR

    def test_managed_by_organization_when_policy_sourced_and_flagged(self, stub, unmanaged):
        managed = ManagementInfo(managed=True, sources=("GroupPolicy",))
        stub.next_value = 0  # would otherwise mismatch/FAIL
        control = _stub_control(management_detection=True)
        control = control.__class__(**{**control.__dict__, "audit": {"primitive": "test_stub", "params": {"_raw": {}}}})
        # Simulate a primitive that reports a policy_source in raw evidence.
        original_probe = stub.probe

        def probe_with_policy_source(params):
            r = original_probe(params)
            r.raw["policy_source"] = "Registry Policy key (SOFTWARE\\Policies)"
            return r

        stub.probe = probe_with_policy_source
        result = evaluate_control(control, managed)
        assert result.status == Status.MANAGED_BY_ORGANIZATION

    def test_not_managed_when_management_detection_false_even_if_policy_sourced(self, stub, unmanaged):
        stub.next_value = 0
        original_probe = stub.probe

        def probe_with_policy_source(params):
            r = original_probe(params)
            r.raw["policy_source"] = "Registry Policy key (SOFTWARE\\Policies)"
            return r

        stub.probe = probe_with_policy_source
        control = _stub_control(management_detection=False)
        result = evaluate_control(control, ManagementInfo(managed=True, sources=("GroupPolicy",)))
        # management_detection is False on the control, so policy_source must be ignored.
        assert result.status == Status.FAIL


class TestPlanHarden:
    def test_skips_controls_without_remediation(self, stub, unmanaged, env):
        stub.next_value = 0
        control = _stub_control(remediation=None)
        plan = plan_harden([control], env, unmanaged)
        assert plan.to_apply == []
        assert len(plan.skipped) == 1
        assert "no automated remediation" in plan.skipped[0].reason_skipped

    def test_includes_controls_with_remediation_and_mismatch(self, stub, unmanaged, env):
        stub.next_value = 0
        control = _stub_control(remediation={"primitive": "test_stub", "params": {"value": 1}})
        plan = plan_harden([control], env, unmanaged)
        assert len(plan.to_apply) == 1

    def test_excludes_passing_controls(self, stub, unmanaged, env):
        stub.next_value = 1
        control = _stub_control(remediation={"primitive": "test_stub", "params": {"value": 1}})
        plan = plan_harden([control], env, unmanaged)
        assert plan.to_apply == []

    def test_high_impact_requires_flag(self, stub, unmanaged, env):
        stub.next_value = 0
        control = _stub_control(
            remediation={"primitive": "test_stub", "params": {"value": 1}}, high_impact=True
        )
        plan = plan_harden([control], env, unmanaged, allow_high_impact=False)
        assert plan.to_apply == []
        assert "high-impact" in plan.skipped[0].reason_skipped

        plan2 = plan_harden([control], env, unmanaged, allow_high_impact=True)
        assert len(plan2.to_apply) == 1


class TestApplyHardenAndRollback:
    def test_apply_then_rollback_restores_original_value(self, stub, unmanaged, env, tmp_path):
        stub.next_value = 0
        control = _stub_control(remediation={"primitive": "test_stub", "params": {"value": 1}})
        plan = plan_harden([control], env, unmanaged)
        tx_manager = TransactionManager(root=str(tmp_path))

        report = apply_harden(plan, [control], env, unmanaged, "test-profile", tx_manager=tx_manager)
        assert report.applied[0].outcome == "applied"
        assert stub.next_value == 1

        from auditforge.rollback.executor import rollback_transaction

        rb = rollback_transaction(report.tx.tx_id, tx_manager)
        assert rb.all_restored
        assert stub.next_value == 0

    def test_apply_failure_does_not_abort_remaining_controls(self, stub, unmanaged, env, tmp_path):
        stub.next_value = 0
        stub.raise_on_apply = RuntimeError("simulated failure")
        control = _stub_control(remediation={"primitive": "test_stub", "params": {"value": 1}})
        plan = plan_harden([control], env, unmanaged)
        tx_manager = TransactionManager(root=str(tmp_path))
        report = apply_harden(plan, [control], env, unmanaged, "test-profile", tx_manager=tx_manager)
        assert report.applied[0].outcome == "failed"
        assert report.tx.status == "partial"


class TestRunAudit:
    def test_summary_counts_and_score(self, stub, unmanaged, env):
        stub.next_value = 1
        control = _stub_control()
        report = run_audit([control, control], env, unmanaged, "test-profile")
        summary = report.summary()
        assert summary["counts"]["PASS"] == 2
        assert summary["score_percent"] == 100.0
