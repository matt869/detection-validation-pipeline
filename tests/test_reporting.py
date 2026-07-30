"""Report rendering."""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

import pytest

from harness.analysis.coverage import AttackReference, CoverageTargets, build_coverage
from harness.analysis.gates import evaluate_gates
from harness.core.config import GateSettings
from harness.core.models import CaseResult, CaseStatus, Outcome
from harness.reporting import FORMATS, render_json, render_markdown, write_reports
from harness.reporting.html import render_html
from harness.reporting.junit import render_junit
from harness.reporting.navigator import build_layer
from harness.reporting.template import escape, render
from tests.conftest import make_case, make_emulation, make_run


def case(outcome, status=CaseStatus.PASS, *, rule="rule_a", technique="T1059.001", **kw):
    return CaseResult(
        case=make_case(rule_name=rule, technique=technique, **kw),
        outcome=outcome,
        status=status,
        detection_hits=1 if outcome is Outcome.DETECTED else 0,
        telemetry_hits=0 if outcome is Outcome.BLIND else 4,
        latency_seconds=3.2 if outcome is Outcome.DETECTED else None,
        emulation=make_emulation(),
        notes=["a note about this case"],
        queries={"detection": "index=windows EventCode=1"},
    )


@pytest.fixture
def sample_run():
    return make_run(
        [
            case(Outcome.DETECTED, rule="detected_rule"),
            case(Outcome.VISIBLE, CaseStatus.FAIL, rule="visible_rule"),
            case(Outcome.BLIND, rule="blind_rule", technique="T1003.001"),
        ]
    )


@pytest.fixture
def sample_coverage(sample_run):
    return build_coverage(
        sample_run, reference=AttackReference.empty(), targets=CoverageTargets.empty()
    )


# --------------------------------------------------------------- templating


def test_placeholders_are_escaped_by_default():
    assert render("{{ x }}", {"x": "<script>"}) == "&lt;script&gt;"


def test_raw_placeholder_inserts_markup():
    assert render("{{& x }}", {"x": "<b>hi</b>"}) == "<b>hi</b>"


def test_missing_key_renders_empty_rather_than_raising():
    # A report with one blank section beats no report at all.
    assert render("a{{ missing }}b", {}) == "ab"


def test_escape_covers_quotes_for_attribute_safety():
    assert escape('a"b') == "a&quot;b"


# --------------------------------------------------------------------- json


def test_json_is_valid_and_complete(sample_run, sample_coverage):
    payload = json.loads(render_json(sample_run, coverage=sample_coverage))
    assert payload["run_id"] == sample_run.run_id
    assert len(payload["results"]) == 3
    assert payload["summary"]["by_outcome"]["blind"] == 1
    assert "coverage" in payload


def test_json_includes_gates_when_supplied(sample_run):
    gates = evaluate_gates(sample_run, GateSettings())
    payload = json.loads(render_json(sample_run, gates=gates))
    assert payload["gates"]["passed"] is False


# ----------------------------------------------------------------- markdown


def test_markdown_leads_with_the_verdict(sample_run):
    gates = evaluate_gates(sample_run, GateSettings())
    body = render_markdown(sample_run, gates=gates)
    assert body.startswith("# Detection validation - FAIL")


def test_markdown_separates_the_two_gap_queues(sample_run):
    body = render_markdown(sample_run)
    assert "## Detection gaps" in body
    assert "## Visibility gaps" in body
    detection_section = body.split("## Detection gaps")[1].split("##")[0]
    assert "visible_rule" in detection_section
    assert "blind_rule" not in detection_section


def test_markdown_explains_who_owns_each_gap(sample_run):
    body = render_markdown(sample_run)
    assert "These belong to detection engineering" in body
    assert "These belong to the platform team" in body


# --------------------------------------------------------------------- html


def test_html_is_self_contained(sample_run, sample_coverage):
    body = render_html(sample_run, coverage=sample_coverage)
    assert body.startswith("<!DOCTYPE html>")
    assert "<style>" in body
    # No external requests: it must render years later on an offline machine.
    assert "http://" not in body
    assert "<script src" not in body


def test_html_escapes_content(sample_run):
    sample_run.results[0].notes = ["<img src=x onerror=alert(1)>"]
    body = render_html(sample_run)
    assert "<img src=x" not in body
    assert "&lt;img" in body


def test_html_shows_the_verdict(sample_run):
    gates = evaluate_gates(sample_run, GateSettings())
    assert 'class="verdict fail"' in render_html(sample_run, gates=gates)


# -------------------------------------------------------------------- junit


def test_junit_is_well_formed(sample_run):
    root = ET.fromstring(render_junit(sample_run))
    assert root.tag == "testsuites"
    assert root.get("tests") == "3"
    assert root.get("failures") == "1"


def test_junit_maps_error_to_error_not_failure():
    # "We could not tell" must never render as a pass in CI.
    run = make_run([case(Outcome.ERROR, CaseStatus.ERROR)])
    root = ET.fromstring(render_junit(run))
    assert root.find(".//error") is not None
    assert root.find(".//failure") is None


def test_junit_records_unexpected_pass_without_failing_the_build():
    run = make_run([case(Outcome.DETECTED, CaseStatus.UNEXPECTED_PASS)])
    root = ET.fromstring(render_junit(run))
    assert root.get("failures") == "0"
    assert "stale" in root.find(".//system-out").text


def test_junit_groups_by_technique(sample_run):
    root = ET.fromstring(render_junit(sample_run))
    classnames = {c.get("classname") for c in root.iter("testcase")}
    assert any("T1003.001" in name for name in classnames)


def test_junit_failure_body_carries_the_query(sample_run):
    root = ET.fromstring(render_junit(sample_run))
    failure = root.find(".//failure")
    assert "detection query: index=windows EventCode=1" in failure.text


# ---------------------------------------------------------------- navigator


def test_navigator_layer_shape(sample_run, sample_coverage):
    layer = build_layer(sample_run, sample_coverage)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1059.001", "T1003.001"}


def test_navigator_scores_are_measured_not_rule_counts(sample_run, sample_coverage):
    layer = build_layer(sample_run, sample_coverage)
    blind = next(t for t in layer["techniques"] if t["techniqueID"] == "T1003.001")
    assert blind["score"] == 0
    assert blind["color"] == "#c0392b"


def test_navigator_metadata_explains_the_state(sample_run, sample_coverage):
    layer = build_layer(sample_run, sample_coverage)
    entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1003.001")
    names = {m["name"] for m in entry["metadata"]}
    assert {"status", "visibility gap", "detection rate"} <= names


def test_navigator_marks_excluded_techniques_disabled(sample_run):
    coverage = build_coverage(
        sample_run,
        reference=AttackReference.empty(),
        targets=CoverageTargets(excluded={"T1204": "owned by the email team"}),
    )
    layer = build_layer(sample_run, coverage)
    excluded = next(t for t in layer["techniques"] if t["techniqueID"] == "T1204")
    assert excluded["enabled"] is False


# ------------------------------------------------------------------ writing


def test_write_reports_produces_every_format(tmp_path, sample_run, sample_coverage):
    written = write_reports(
        sample_run, tmp_path, formats=FORMATS, coverage=sample_coverage
    )
    assert {p.name for p in written} == {
        "report.json",
        "report.md",
        "report.html",
        "junit.xml",
        "navigator-layer.json",
    }
    assert all(p.exists() and p.stat().st_size > 0 for p in written)


def test_reports_land_in_a_per_run_directory(tmp_path, sample_run):
    written = write_reports(sample_run, tmp_path, formats=("json",))
    assert written[0].parent.name == sample_run.run_id


def test_latest_pointer_is_updated(tmp_path, sample_run):
    write_reports(sample_run, tmp_path, formats=("json",))
    assert (tmp_path / "LATEST").read_text(encoding="utf-8").strip() == sample_run.run_id


def test_unknown_format_is_rejected(tmp_path, sample_run):
    from harness.core.errors import UsageError

    with pytest.raises(UsageError, match="unknown report format"):
        write_reports(sample_run, tmp_path, formats=("pdf",))


def test_navigator_is_skipped_without_coverage(tmp_path, sample_run):
    written = write_reports(sample_run, tmp_path, formats=("json", "navigator"))
    assert [p.name for p in written] == ["report.json"]
