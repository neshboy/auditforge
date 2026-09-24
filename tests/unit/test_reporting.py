import json

import pytest

from auditforge.reporting.generator import render, render_csv, render_html, render_json, render_markdown, _format_expected


def _sample_report():
    return {
        "hostname": "test-host",
        "os": "windows",
        "os_name": "Windows 11",
        "os_version": "24H2",
        "architecture": "AMD64",
        "profile": "standard",
        "generated_at": "2026-09-24T00:00:00Z",
        "management": {"managed": False, "sources": []},
        "summary": {
            "counts": {
                "PASS": 1, "FAIL": 1, "WARNING": 0, "NOT_APPLICABLE": 0,
                "MANUAL_REVIEW": 0, "MANAGED_BY_ORGANIZATION": 0, "ERROR": 0,
            },
            "by_category": {
                "accounts": {
                    "PASS": 1, "FAIL": 1, "WARNING": 0, "NOT_APPLICABLE": 0,
                    "MANUAL_REVIEW": 0, "MANAGED_BY_ORGANIZATION": 0, "ERROR": 0,
                }
            },
            "total_controls": 2,
            "score_percent": 50.0,
        },
        "results": [
            {
                "control_id": "AF-TEST-001",
                "title": "A passing control",
                "description": "desc",
                "os": "windows",
                "category": "accounts",
                "severity": "high",
                "benchmark": "Test",
                "benchmark_version": "1",
                "external_reference": "https://example.invalid",
                "rationale": "because",
                "expected_value": 1,
                "possible_impact": "none",
                "reboot_required": False,
                "service_restart_required": False,
                "remediation_available": True,
                "status": "PASS",
                "message": "Compliant",
                "evidence": {"detected_value": 1, "expected_value": 1, "source": "test", "timestamp": "now", "raw": {}},
                "remediation_applied": False,
                "remediation_status": None,
                "error": None,
                "frameworks": {},
            },
            {
                "control_id": "AF-TEST-002",
                "title": "A failing control",
                "description": "desc",
                "os": "windows",
                "category": "accounts",
                "severity": "high",
                "benchmark": "Test",
                "benchmark_version": "1",
                "external_reference": "https://example.invalid",
                "rationale": "because",
                "expected_value": {"min": 15},
                "possible_impact": "none",
                "reboot_required": False,
                "service_restart_required": False,
                "remediation_available": True,
                "status": "FAIL",
                "message": "Expected {'min': 15}, found 0",
                "evidence": {"detected_value": 0, "expected_value": {"min": 15}, "source": "test", "timestamp": "now", "raw": {}},
                "remediation_applied": False,
                "remediation_status": None,
                "error": None,
                "frameworks": {},
            },
        ],
    }


def test_render_json_roundtrips():
    report = _sample_report()
    text = render_json(report)
    parsed = json.loads(text)
    assert parsed["hostname"] == "test-host"
    assert len(parsed["results"]) == 2


def test_render_csv_has_one_row_per_control():
    text = render_csv(_sample_report())
    lines = [l for l in text.splitlines() if l.strip()]
    assert len(lines) == 3  # header + 2 controls
    assert "AF-TEST-001" in text
    assert "AF-TEST-002" in text


def test_render_markdown_includes_findings_not_passes():
    text = render_markdown(_sample_report())
    assert "AF-TEST-002" in text
    assert "A failing control" in text
    # The passing control should not appear under Findings.
    assert "A passing control" not in text


def test_render_html_is_well_formed_and_has_no_unrendered_template_syntax():
    html = render_html(_sample_report())
    assert "{{" not in html
    assert "{%" not in html
    assert "AF-TEST-002" in html
    assert "<html" in html and "</html>" in html


def test_render_html_never_puts_dict_repr_in_output():
    html = render_html(_sample_report())
    assert "{'min': 15}" not in html
    assert ">= 15" in html


def test_render_unsupported_format_raises():
    with pytest.raises(ValueError):
        render(_sample_report(), "pdf-but-not-really")


def test_format_expected_helper():
    assert _format_expected({"min": 15}) == ">= 15"
    assert _format_expected({"max": 5}) == "<= 5"
    assert _format_expected({"min": 1, "max": 10}) == ">= 1 and <= 10"
    assert _format_expected({"one_of": ["a", "b"]}) == "one of: a, b"
    assert _format_expected(True) is True
    assert _format_expected("Disabled") == "Disabled"
