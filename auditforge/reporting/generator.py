"""Report generation: JSON, CSV, Markdown, and a self-contained HTML
dashboard, all built from the same AuditReport.to_dict() structure so every
format shows the same numbers.
"""

from __future__ import annotations

import csv
import io
import json
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_CATEGORY_DISPLAY_OVERRIDES = {
    "uac": "User Account Control",
    "ssh": "SSH",
    "smb": "SMB",
    "boot_integrity": "Boot Integrity",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATUS_PRIORITY = {
    "FAIL": 0,
    "ERROR": 1,
    "WARNING": 2,
    "MANUAL_REVIEW": 3,
    "MANAGED_BY_ORGANIZATION": 4,
    "NOT_APPLICABLE": 5,
    "PASS": 6,
}


def _category_display(name: str) -> str:
    if name in _CATEGORY_DISPLAY_OVERRIDES:
        return _CATEGORY_DISPLAY_OVERRIDES[name]
    return name.replace("_", " ").title()


def render_json(report_dict: dict) -> str:
    return json.dumps(report_dict, indent=2, default=str)


def render_csv(report_dict: dict) -> str:
    buf = io.StringIO()
    fieldnames = [
        "control_id", "title", "category", "severity", "status", "message",
        "detected_value", "expected_value", "benchmark", "external_reference",
        "remediation_available", "reboot_required", "service_restart_required",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in report_dict["results"]:
        row = dict(r)
        row["detected_value"] = r["evidence"]["detected_value"]
        row["expected_value"] = r["evidence"]["expected_value"]
        writer.writerow(row)
    return buf.getvalue()


def render_markdown(report_dict: dict) -> str:
    lines = []
    lines.append(f"# AuditForge Security Assessment: {report_dict['hostname']}")
    lines.append("")
    lines.append(f"- **OS:** {report_dict['os_name']} {report_dict['os_version']} ({report_dict['architecture']})")
    lines.append(f"- **Profile:** {report_dict['profile']}")
    lines.append(f"- **Generated:** {report_dict['generated_at']}")
    managed = report_dict["management"]
    mgmt_line = "Yes (" + ", ".join(managed["sources"]) + ")" if managed["managed"] else "No"
    lines.append(f"- **Centrally managed:** {mgmt_line}")
    score = report_dict["summary"]["score_percent"]
    lines.append(f"- **Overall score:** {score if score is not None else 'n/a'}%")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---|")
    for status, count in report_dict["summary"]["counts"].items():
        lines.append(f"| {status} | {count} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = [r for r in report_dict["results"] if r["status"] in ("FAIL", "WARNING", "MANUAL_REVIEW", "ERROR")]
    findings.sort(key=lambda r: (_STATUS_PRIORITY.get(r["status"], 9), _SEVERITY_RANK.get(r["severity"], 9)))
    if not findings:
        lines.append("_No findings -- everything evaluated passed, was not applicable, or is managed externally._")
    for r in findings:
        lines.append(f"### {r['control_id']}: {r['title']}")
        lines.append("")
        lines.append(f"- **Status:** {r['status']}")
        lines.append(f"- **Severity:** {r['severity']}")
        lines.append(f"- **Observed:** {r['evidence']['detected_value']}")
        lines.append(f"- **Expected:** {_format_expected(r['evidence']['expected_value'])}")
        lines.append(f"- **Why:** {r['rationale'].strip()}")
        lines.append(f"- **Reference:** {r['external_reference']}")
        lines.append(f"- **Remediation available:** {'YES' if r['remediation_available'] else 'NO'}")
        if r["reboot_required"]:
            lines.append("- **Reboot:** possibly required")
        lines.append("")
    return "\n".join(lines)


def _build_html_context(report_dict: dict) -> dict:
    summary = report_dict["summary"]
    counts = summary["counts"]

    categories = []
    for cat_name, cat_counts in summary["by_category"].items():
        total_scored = cat_counts["PASS"] + cat_counts["FAIL"] + cat_counts["WARNING"]
        score = round(100 * cat_counts["PASS"] / total_scored, 1) if total_scored else None
        categories.append(
            {
                "name": cat_name,
                "display_name": _category_display(cat_name),
                "counts": cat_counts,
                "score": score,
            }
        )
    categories.sort(key=lambda c: (c["score"] if c["score"] is not None else 999))

    findings = [r for r in report_dict["results"] if r["status"] in ("FAIL", "WARNING", "MANUAL_REVIEW", "ERROR")]
    findings.sort(key=lambda r: (_STATUS_PRIORITY.get(r["status"], 9), _SEVERITY_RANK.get(r["severity"], 9)))

    other = [r for r in report_dict["results"] if r["status"] in ("NOT_APPLICABLE", "MANAGED_BY_ORGANIZATION")]
    passed = [r for r in report_dict["results"] if r["status"] == "PASS"]

    score = summary["score_percent"]
    if score is None:
        score_band = "unknown"
    elif score >= 90:
        score_band = "good"
    elif score >= 70:
        score_band = "warning"
    else:
        score_band = "critical"

    return {
        "report": report_dict,
        "counts": counts,
        "categories": categories,
        "findings": findings,
        "other_results": other,
        "passed_results": passed,
        "score": score,
        "score_band": score_band,
    }


def _format_expected(value) -> str:
    if isinstance(value, dict):
        if "one_of" in value:
            return "one of: " + ", ".join(str(v) for v in value["one_of"])
        parts = []
        if "min" in value:
            parts.append(f">= {value['min']}")
        if "max" in value:
            parts.append(f"<= {value['max']}")
        if "not" in value:
            parts.append(f"not {value['not']!r}")
        return " and ".join(parts) if parts else str(value)
    return value


def render_html(report_dict: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["format_expected"] = _format_expected
    template = env.get_template("report.html.j2")
    return template.render(**_build_html_context(report_dict))


_WRITERS = {
    "json": render_json,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}


def render(report_dict: dict, fmt: str) -> str:
    try:
        return _WRITERS[fmt.lower()](report_dict)
    except KeyError as exc:
        raise ValueError(f"unsupported report format '{fmt}', expected one of {sorted(_WRITERS)}") from exc


def write_report(report_dict: dict, fmt: str, path: str) -> None:
    content = render(report_dict, fmt)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
