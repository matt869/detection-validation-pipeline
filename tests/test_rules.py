"""Rule parsing, validation, and library selection."""

from __future__ import annotations

import pytest

from harness.core.errors import RuleError
from harness.core.models import Outcome, RuleStatus, Severity
from harness.core.yamlio import StrictLoader
from rulekit.library import load_library
from rulekit.rule import Rule

MINIMAL = {
    "title": "Test",
    "detection": {"selection": {"EventID": 1}, "condition": "selection"},
}


def test_minimal_rule_loads():
    rule = Rule.from_dict(MINIMAL)
    assert rule.title == "Test"
    assert rule.status is RuleStatus.EXPERIMENTAL
    assert rule.severity is Severity.MEDIUM


@pytest.mark.parametrize("missing", ["title", "detection"])
def test_required_keys(missing):
    document = {k: v for k, v in MINIMAL.items() if k != missing}
    with pytest.raises(RuleError, match="missing required key"):
        Rule.from_dict(document)


def test_detection_without_condition_is_rejected():
    with pytest.raises(RuleError, match="no 'condition'"):
        Rule.from_dict({"title": "T", "detection": {"selection": {"EventID": 1}}})


def test_invalid_condition_reports_the_position():
    with pytest.raises(RuleError, match="invalid condition"):
        Rule.from_dict(
            {"title": "T", "detection": {"selection": {"A": 1}, "condition": "selection and ?"}}
        )


def test_bad_modifier_fails_at_load_not_at_query_time():
    with pytest.raises(RuleError, match="unknown modifier"):
        Rule.from_dict(
            {
                "title": "T",
                "detection": {"selection": {"Image|endswithh": "x"}, "condition": "selection"},
            }
        )


def test_condition_list_is_joined_as_or():
    rule = Rule.from_dict(
        {
            "title": "T",
            "detection": {
                "a": {"X": 1},
                "b": {"Y": 2},
                "condition": ["a", "b"],
            },
        }
    )
    assert rule.referenced_selections == {"a", "b"}


# ------------------------------------------------------------------- attack


def test_attack_structured_form():
    rule = Rule.from_dict(
        {**MINIMAL, "attack": {"tactics": ["execution"], "techniques": ["T1059.001"]}}
    )
    assert rule.technique_ids == ["T1059.001"]
    assert rule.tactics == ["execution"]
    assert rule.attack[0].subtechnique_of == "T1059"


def test_attack_flat_list_form():
    rule = Rule.from_dict({**MINIMAL, "attack": ["T1003", "T1003.001"]})
    assert rule.technique_ids == ["T1003", "T1003.001"]


def test_malformed_technique_id_is_rejected():
    with pytest.raises(RuleError, match="invalid ATT&CK technique"):
        Rule.from_dict({**MINIMAL, "attack": ["T99"]})


# --------------------------------------------------------------- validation


def test_validation_defaults_to_expecting_detection():
    assert Rule.from_dict(MINIMAL).validation.expect is Outcome.DETECTED


def test_accepted_gap_requires_a_justification():
    # An accepted gap with no reason is indistinguishable from a broken rule
    # somebody silenced.
    with pytest.raises(RuleError, match="no justification"):
        Rule.from_dict({**MINIMAL, "validation": {"expect": "blind"}})


def test_accepted_gap_with_justification_loads():
    rule = Rule.from_dict(
        {
            **MINIMAL,
            "validation": {
                "expect": "blind",
                "justification": "channel not onboarded, SEC-4471",
                "owner": "endpoint-engineering",
            },
        }
    )
    assert rule.validation.expect is Outcome.BLIND


def test_operational_states_are_not_valid_expectations():
    with pytest.raises(RuleError, match="operational states are not expectations"):
        Rule.from_dict({**MINIMAL, "validation": {"expect": "error"}})


def test_unknown_expectation_is_rejected():
    with pytest.raises(RuleError, match="must be one of"):
        Rule.from_dict({**MINIMAL, "validation": {"expect": "maybe"}})


def test_max_latency_accepts_duration_strings():
    rule = Rule.from_dict({**MINIMAL, "validation": {"max_latency": "5m"}})
    assert rule.validation.max_latency_seconds == 300.0


# ------------------------------------------------------------- derived data


def test_unused_selections_are_detected():
    rule = Rule.from_dict(
        {
            "title": "T",
            "detection": {
                "selection": {"A": 1},
                "orphan": {"B": 2},
                "condition": "selection",
            },
        }
    )
    assert rule.unused_selections == ["orphan"]


def test_fingerprint_ignores_prose_but_tracks_logic():
    base = {**MINIMAL, "telemetry": ["x"]}
    original = Rule.from_dict(base)
    reworded = Rule.from_dict({**base, "description": "completely different prose"})
    relogicked = Rule.from_dict(
        {**base, "detection": {"selection": {"EventID": 2}, "condition": "selection"}}
    )
    assert original.fingerprint == reworded.fingerprint
    assert original.fingerprint != relogicked.fingerprint


def test_field_names_are_collected_across_selections():
    rule = Rule.from_dict(
        {
            "title": "T",
            "detection": {
                "a": {"Image|endswith": "x", "EventID": 1},
                "b": {"ParentImage": "y"},
                "condition": "a and b",
            },
        }
    )
    assert rule.field_names == ["Image", "EventID", "ParentImage"]


# ------------------------------------------------------------------ loading


def test_duplicate_yaml_keys_are_rejected(tmp_path):
    # A second `selection:` silently replaces the first, deleting detection
    # logic with no warning. That has shipped broken rules before.
    import yaml

    path = tmp_path / "dup.yml"
    path.write_text("title: T\nselection: a\nselection: b\n", encoding="utf-8")
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)


def test_library_load_is_fault_tolerant(tmp_path):
    (tmp_path / "good.yml").write_text(
        "title: Good\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yml").write_text("title: Bad\n", encoding="utf-8")

    library = load_library(tmp_path)
    assert len(library) == 1
    assert len(library.errors) == 1
    assert "bad.yml" in str(library.errors[0])


def test_library_strict_mode_raises(tmp_path):
    (tmp_path / "bad.yml").write_text("title: Bad\n", encoding="utf-8")
    with pytest.raises(RuleError):
        load_library(tmp_path, strict=True)


def test_underscore_directories_are_not_loaded_as_rules(workspace):
    # detections/_shared/template.yml must never become a rule.
    assert "template" not in workspace.rules


def test_technique_selection_is_hierarchical(workspace):
    # Asking for a parent technique selects its sub-techniques, because that is
    # what an operator means by "show me credential dumping coverage".
    parent = workspace.rules.select(techniques=["T1003"])
    assert any("T1003.001" in r.technique_ids for r in parent)


def test_severity_floor_filters(workspace):
    critical = workspace.rules.select(min_severity=Severity.CRITICAL)
    assert critical
    assert all(r.severity >= Severity.CRITICAL for r in critical)


def test_unknown_rule_name_suggests_a_close_match(workspace):
    with pytest.raises(RuleError) as excinfo:
        workspace.rules.require("lsass_memory_acces")
    assert "Did you mean 'lsass_memory_access'" in (excinfo.value.hint or "")
