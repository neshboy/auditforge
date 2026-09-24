"""AuditForge command-line interface.

    auditforge audit [--profile NAME] [--format json,html,csv,markdown] [--output DIR]
    auditforge harden [--profile NAME] [--dry-run] [--allow-high-impact] [--yes]
    auditforge rollback <transaction_id> | --list
    auditforge verify [transaction_id]
    auditforge framework status

Running with no subcommand launches the interactive menu (section 20 of
the project spec).
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

import yaml

from auditforge.core.bootstrap import load_primitives_for
from auditforge.core.control_loader import filter_by_categories, filter_by_ids, load_controls_for_os
from auditforge.core.engine import apply_harden, plan_harden, run_audit
from auditforge.core.environment import detect_environment, detect_management
from auditforge.core.models import Status
from auditforge.core.paths import controls_base_dir, frameworks_dir
from auditforge.core.profile_loader import apply_profile_filter, list_profiles, load_profile
from auditforge.reporting.generator import write_report
from auditforge.rollback.executor import rollback_transaction
from auditforge.rollback.transaction import TransactionManager

DEFAULT_REPORT_DIR = "reports"


def _load_controls(env, args) -> list:
    load_primitives_for(env.os)
    controls = load_controls_for_os(env.os, controls_base_dir())
    profile = load_profile(args.profile)
    controls = apply_profile_filter(controls, profile)
    if getattr(args, "control", None):
        controls = filter_by_ids(controls, args.control)
    if getattr(args, "categories", None):
        controls = filter_by_categories(controls, args.categories)
    return controls, profile


def _emit_report(report_dict: dict, args, label: str) -> list:
    formats = [f.strip() for f in (args.format or "html,json").split(",") if f.strip()]
    outdir = args.output or DEFAULT_REPORT_DIR
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    written = []
    for fmt in formats:
        ext = "md" if fmt == "markdown" else fmt
        path = os.path.join(outdir, f"{label}-{report_dict['hostname']}-{stamp}.{ext}")
        write_report(report_dict, fmt, path)
        written.append(path)
    return written


def _print_summary(report) -> None:
    s = report.summary()
    print(f"Host:    {report.environment.hostname}")
    print(f"OS:      {report.environment.os_name} {report.environment.os_version} ({report.environment.architecture})")
    print(f"Profile: {report.profile}")
    score = s["score_percent"]
    print(f"Score:   {score}%" if score is not None else "Score:   n/a (nothing scoreable)")
    print()
    for status in ("PASS", "FAIL", "WARNING", "MANUAL_REVIEW", "MANAGED_BY_ORGANIZATION", "NOT_APPLICABLE", "ERROR"):
        print(f"  {status:26s} {s['counts'].get(status, 0)}")


def cmd_audit(args) -> int:
    env = detect_environment()
    mgmt = detect_management(env)
    controls, profile = _load_controls(env, args)
    report = run_audit(controls, env, mgmt, profile.name)
    _print_summary(report)
    written = _emit_report(report.to_dict(), args, "audit")
    print("\nReports written:")
    for path in written:
        print(f"  {path}")
    return 0


def _print_plan(plan) -> None:
    print(f"Controls that WOULD be changed: {len(plan.to_apply)}")
    for p in plan.to_apply:
        print(f"  [{p.control.severity.value:8s}] {p.control.control_id:18s} {p.control.title}")
        print(f"             current={p.current_result.evidence.detected_value!r} -> expected={p.control.expected_value!r}")
        if p.control.reboot_required:
            print("             (reboot may be required)")
    print(f"\nControls skipped: {len(plan.skipped)}")
    for p in plan.skipped:
        print(f"  {p.control.control_id:18s} {p.control.title}  -- {p.reason_skipped}")


def cmd_harden(args) -> int:
    env = detect_environment()
    mgmt = detect_management(env)
    controls, profile = _load_controls(env, args)

    allow_high_impact = args.allow_high_impact or profile.allow_high_impact
    plan = plan_harden(controls, env, mgmt, allow_high_impact=allow_high_impact)
    _print_plan(plan)

    if args.dry_run:
        print("\n[DRY RUN] No changes were applied.")
        return 0
    if profile.audit_only:
        print(f"\nProfile '{profile.name}' is audit_only -- no changes were applied regardless of flags.")
        return 0
    if not plan.to_apply:
        print("\nNothing to apply.")
        return 0

    if not args.yes:
        answer = input(f"\nApply {len(plan.to_apply)} change(s) to {env.hostname}? Type 'yes' to continue: ")
        if answer.strip().lower() != "yes":
            print("Aborted -- no changes applied.")
            return 1

    tx_manager = TransactionManager()
    report = apply_harden(plan, controls, env, mgmt, profile.name, tx_manager=tx_manager)

    print(f"\nTransaction: {report.tx.tx_id}")
    for a in report.applied:
        print(f"  [{a.outcome:12s}] {a.control_id:18s} {a.message}")

    before = {r.control.control_id: r.status for r in report.pre_audit.results}
    after_counts = report.post_audit.summary()["counts"]
    print("\nPost-hardening summary:")
    for status in ("PASS", "FAIL", "WARNING"):
        print(f"  {status:10s} {after_counts.get(status, 0)}")

    _emit_report(report.post_audit.to_dict(), args, "harden")
    print(f"\nTo undo this run: auditforge rollback {report.tx.tx_id}")
    failed = [a for a in report.applied if a.outcome != "applied"]
    return 1 if failed else 0


def cmd_rollback(args) -> int:
    manager = TransactionManager()
    if args.list:
        for tx in manager.list_transactions():
            print(f"{tx['tx_id']}  {tx['started_at']}  status={tx['status']}  changes={tx['num_changes']}  profile={tx['profile']}")
        return 0
    if not args.transaction_id:
        print("Specify a transaction id, or use --list to see available transactions.", file=sys.stderr)
        return 2
    report = rollback_transaction(args.transaction_id, manager)
    for item in report.items:
        print(f"  [{'OK' if item.restored else 'FAILED':6s}] {item.control_id:18s} {item.message}")
    if report.all_restored:
        print("\nAll changes restored.")
        return 0
    print("\nPARTIAL rollback -- some changes could not be restored automatically; see above.")
    return 1


def cmd_verify(args) -> int:
    manager = TransactionManager()
    tx_id = args.transaction_id
    if not tx_id:
        txs = manager.list_transactions()
        if not txs:
            print("No transactions found.", file=sys.stderr)
            return 1
        tx_id = txs[0]["tx_id"]
    tx = manager.load(tx_id)
    if not tx.changes:
        print(f"Transaction {tx_id} recorded no changes (dry run or nothing to apply).")
        return 0

    env = detect_environment()
    load_primitives_for(env.os)
    mgmt = detect_management(env)
    all_controls = load_controls_for_os(env.os, controls_base_dir())
    changed_ids = {c.control_id for c in tx.changes}
    targets = filter_by_ids(all_controls, changed_ids)

    report = run_audit(targets, env, mgmt)
    print(f"Verifying transaction {tx_id} ({len(targets)} control(s)):\n")
    drifted = []
    for r in report.results:
        print(f"  {r.control.control_id:18s} {r.status.value}")
        if r.status != Status.PASS:
            drifted.append(r)

    if drifted:
        print(f"\n{len(drifted)} control(s) have drifted from the applied state (configuration drift detected).")
        return 1
    print("\nNo drift detected; all previously-applied controls remain in effect.")
    return 0


def cmd_framework_status(args) -> int:
    for fname in ("nist", "disa", "microsoft", "apple"):
        path = os.path.join(frameworks_dir(), f"{fname}.yml")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        print(data.get("display_name", fname))
        for pub in data.get("publications", []):
            print(f"  {pub['title'][:64]:64s} {pub['status']}")
        print()
    return 0


def cmd_profiles(args) -> int:
    for name in list_profiles():
        profile = load_profile(name)
        print(f"{profile.name:16s} {profile.display_name}")
        print(f"  {profile.description.strip()}")
        print()
    return 0


MENU = """
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
"""


def run_menu(parser: argparse.ArgumentParser) -> int:
    while True:
        print(MENU)
        choice = input("> ").strip()
        if choice == "1":
            _dispatch(parser, ["audit"])
        elif choice == "2":
            _dispatch(parser, ["harden", "--dry-run"])
        elif choice == "3":
            _dispatch(parser, ["harden", "--profile", "workstation"])
        elif choice == "4":
            _dispatch(parser, ["harden", "--profile", "strict", "--allow-high-impact"])
        elif choice == "5":
            _dispatch(parser, ["audit", "--format", "html,json,csv,markdown"])
        elif choice == "6":
            _dispatch(parser, ["verify"])
        elif choice == "7":
            _dispatch(parser, ["rollback", "--list"])
            tx_id = input("Enter a transaction ID to roll back (blank to cancel): ").strip()
            if tx_id:
                _dispatch(parser, ["rollback", tx_id])
        elif choice == "8":
            _dispatch(parser, ["profiles"])
            _dispatch(parser, ["framework", "status"])
        elif choice == "9":
            return 0
        else:
            print("Invalid choice.")


def _dispatch(parser: argparse.ArgumentParser, argv: list) -> int:
    try:
        args = parser.parse_args(argv)
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001 -- keep the interactive menu alive on error
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditforge", description="Cross-platform endpoint security audit and hardening framework")
    sub = parser.add_subparsers(dest="command")

    common = dict(add_help=False)

    audit_p = sub.add_parser("audit", help="Run a read-only security audit", **common)
    audit_p.add_argument("--profile", default="audit_only")
    audit_p.add_argument("--format", default="html,json", help="comma-separated: json,html,csv,markdown")
    audit_p.add_argument("--output", default=None)
    audit_p.add_argument("--control", action="append", default=None, help="limit to specific control ID(s)")
    audit_p.add_argument("--categories", action="append", default=None)
    audit_p.set_defaults(handler=cmd_audit)

    harden_p = sub.add_parser("harden", help="Audit, then remediate FAIL/WARNING findings", **common)
    harden_p.add_argument("--profile", default="workstation")
    harden_p.add_argument("--dry-run", action="store_true")
    harden_p.add_argument("--allow-high-impact", action="store_true")
    harden_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    harden_p.add_argument("--format", default="html,json")
    harden_p.add_argument("--output", default=None)
    harden_p.add_argument("--control", action="append", default=None)
    harden_p.add_argument("--categories", action="append", default=None)
    harden_p.set_defaults(handler=cmd_harden)

    rollback_p = sub.add_parser("rollback", help="Undo a previous harden transaction", **common)
    rollback_p.add_argument("transaction_id", nargs="?", default=None)
    rollback_p.add_argument("--list", action="store_true")
    rollback_p.set_defaults(handler=cmd_rollback)

    verify_p = sub.add_parser("verify", help="Check whether a previous harden run's changes are still in effect", **common)
    verify_p.add_argument("transaction_id", nargs="?", default=None)
    verify_p.set_defaults(handler=cmd_verify)

    framework_p = sub.add_parser("framework", help="Framework/benchmark update status", **common)
    framework_sub = framework_p.add_subparsers(dest="framework_command")
    fw_status = framework_sub.add_parser("status", **common)
    fw_status.set_defaults(handler=cmd_framework_status)
    framework_p.set_defaults(handler=cmd_framework_status)

    profiles_p = sub.add_parser("profiles", help="List available hardening profiles", **common)
    profiles_p.set_defaults(handler=cmd_profiles)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return run_menu(parser)
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
