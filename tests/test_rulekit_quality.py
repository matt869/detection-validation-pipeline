"""Linters and the rule scorecard."""

from __future__ import annotations

import pytest

from harness.core.models import Outcome
from rulekit.linters import Level, LintContext, filter_findings, lint_rule, summarise
from rulekit.rule import Rule
from rulekit.scorecard import ScoringContext, score_rule
from rulekit.telemetry import TelemetryCatalog, TelemetrySource

GOOD = {
    "id": "6b1f0c2a-9d43-4a17-9f0e-3c2b5a71d804",
    "name": "good_rule",
    "title": "A well-formed rule",
    "status": "production",
    "severity": "high",
    "description": "A description long enough to actually help a responder triage the alert.",
    "author": "detection-engineering",
    "date": "2026-01-01",
    "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    "attack": {"tactics": ["execution"], "techniques": ["T1059.001"]},
    "platforms": ["windows"],
    "telemetry": ["sysmon_process_creation"],
    "fields": ["Computer", "CommandLine"],
    "falsepositives": ["Configuration management encodes commands."],
    "detection": {
        "selection": {"EventID": 1, "CommandLine|contains": "-encodedcommand"},
        "filter_known_good": {"ParentImage|endswith": "\\ccmexec.exe"},
        "condition": "selection and not filter_known_good",
    },
    "validation": {"emulation": ["T1059.001-powershell-encoded"], "expect": "detected"},
}


@pytest.fixture
def context() -> LintContext:
    catalog = TelemetryCatalog(
        sources={
            "sysmon_process_creation": TelemetrySource.from_dict(
                "sysmon_process_creation",
                {
                    "name": "Sysmon 1",
                    "platform": "windows",
                    "owner": "endpoint",
                    "fields": ["EventID", "CommandLine", "ParentImage"],
                    "backends": {"splunk": {"scope": "index=windows EventCode=1"}},
                },
            )
        }
    )
    return LintContext(
        catalog=catalog,
        known_tests=frozenset({"T1059.001-powershell-encoded"}),
        attack={"T1059.001": {"name": "PowerShell", "tactics": ["execution"]}},
        required_dialects=("splunk",),
    )


def codes(rule_document, context, *, level=Level.INFO) -> set[str]:
    findings = lint_rule(Rule.from_dict(rule_document), context)
    return {f.code for f in filter_findings(findings, min_level=level)}


# ------------------------------------------------------------------ clean


def test_a_well_formed_rule_produces_no_errors(context):
    assert codes(GOOD, context, level=Level.ERROR) == set()


# --------------------------------------------------------------- metadata


def test_production_rule_without_an_id_is_an_error(context):
    document = {k: v for k, v in GOOD.items() if k != "id"}
    assert "MD001" in codes(document, context)


def test_non_uuid_id_is_a_warning(context):
    assert "MD002" in codes({**GOOD, "id": "rule-17"}, context)


def test_production_rule_without_a_description_is_an_error(context):
    document = {k: v for k, v in GOOD.items() if k != "description"}
    assert "MD004" in codes(document, context, level=Level.ERROR)


def test_missing_author_and_references_are_flagged(context):
    document = {k: v for k, v in GOOD.items() if k not in ("author", "references")}
    found = codes(document, context)
    assert {"MD005", "MD007"} <= found


def test_unknown_top_level_key_is_reported(context):
    assert "MD008" in codes({**GOOD, "typoed_key": 1}, context)


# ------------------------------------------------------------------ logic


def test_unused_selection_is_an_error(context):
    document = {
        **GOOD,
        "detection": {
            "selection": {"EventID": 1},
            "orphan": {"EventID": 2},
            "condition": "selection",
        },
    }
    assert "LG001" in codes(document, context, level=Level.ERROR)


def test_selection_matching_everything_is_an_error(context):
    document = {
        **GOOD,
        "detection": {"selection": {"Image": "*"}, "condition": "selection"},
    }
    assert "LG002" in codes(document, context, level=Level.ERROR)


def test_very_short_contains_literal_is_a_warning(context):
    document = {
        **GOOD,
        "detection": {
            "selection": {"EventID": 1, "CommandLine|contains": " cl "},
            "filter_known_good": {"ParentImage|endswith": "\\x.exe"},
            "condition": "selection and not filter_known_good",
        },
    }
    assert "LG004" in codes(document, context)


def test_invalid_regex_is_an_error(context):
    document = {
        **GOOD,
        "detection": {"selection": {"CommandLine|re": "([unclosed"}, "condition": "selection"},
    }
    assert "LG005" in codes(document, context, level=Level.ERROR)


def test_single_field_production_rule_is_a_warning(context):
    document = {
        **GOOD,
        "detection": {"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"},
    }
    assert "LG009" in codes(document, context)


def test_duplicate_values_are_reported(context):
    document = {
        **GOOD,
        "detection": {
            "selection": {"EventID": 1, "CommandLine|contains": ["abcd", "ABCD"]},
            "filter_known_good": {"ParentImage|endswith": "\\x.exe"},
            "condition": "selection and not filter_known_good",
        },
    }
    assert "LG007" in codes(document, context)


# ----------------------------------------------------------------- mapping


def test_missing_attack_mapping_is_an_error_for_production(context):
    document = {k: v for k, v in GOOD.items() if k != "attack"}
    assert "AT001" in codes(document, context, level=Level.ERROR)


def test_unmapped_technique_is_a_warning(context):
    assert "AT002" in codes({**GOOD, "attack": ["T9999"]}, context)


def test_parent_technique_with_subtechniques_is_flagged(context):
    context.attack = {"T1059": {"name": "CSI", "subtechniques": ["T1059.001"]}}
    assert "AT006" in codes({**GOOD, "attack": ["T1059"]}, context)


def test_missing_telemetry_is_an_error_for_production(context):
    document = {k: v for k, v in GOOD.items() if k != "telemetry"}
    assert "TM001" in codes(document, context, level=Level.ERROR)


def test_unknown_telemetry_source_is_an_error(context):
    assert "TM002" in codes({**GOOD, "telemetry": ["nope"]}, context, level=Level.ERROR)


def test_field_not_provided_by_the_source_is_a_warning(context):
    document = {
        **GOOD,
        "detection": {
            "selection": {"EventID": 1, "NotAField|contains": "value"},
            "filter_known_good": {"ParentImage|endswith": "\\x.exe"},
            "condition": "selection and not filter_known_good",
        },
    }
    assert "TM005" in codes(document, context)


# -------------------------------------------------------------- validation


def test_rule_without_emulation_is_an_error_for_production(context):
    document = {k: v for k, v in GOOD.items() if k != "validation"}
    assert "VL001" in codes(document, context, level=Level.ERROR)


def test_unknown_emulation_test_is_an_error(context):
    document = {**GOOD, "validation": {"emulation": ["not-a-test"]}}
    assert "VL002" in codes(document, context, level=Level.ERROR)


def test_accepted_gap_is_surfaced(context):
    document = {
        **GOOD,
        "validation": {
            "emulation": ["T1059.001-powershell-encoded"],
            "expect": "blind",
            "justification": "channel not onboarded",
            "owner": "endpoint",
        },
    }
    assert "VL003" in codes(document, context)


def test_accepted_gap_without_an_owner_is_a_warning(context):
    document = {
        **GOOD,
        "validation": {
            "emulation": ["T1059.001-powershell-encoded"],
            "expect": "blind",
            "justification": "channel not onboarded",
        },
    }
    assert "VL006" in codes(document, context)


# ------------------------------------------------------------ portability


def test_missing_dialect_mapping_is_flagged(context):
    context.required_dialects = ("splunk", "sentinel")
    found = codes(GOOD, context)
    # No sentinel table is configured for the source, so the probe warns.
    assert "TM004" in found or "PT001" in found


# --------------------------------------------------------------- filtering


def test_only_and_ignore_select_by_prefix():
    from rulekit.linters.base import Finding

    findings = [
        Finding(code="MD001", level=Level.ERROR, message="a"),
        Finding(code="LG001", level=Level.ERROR, message="b"),
    ]
    assert {f.code for f in filter_findings(findings, only=["MD"])} == {"MD001"}
    assert {f.code for f in filter_findings(findings, ignore=["MD001"])} == {"LG001"}


def test_summarise_counts_by_level():
    from rulekit.linters.base import Finding

    counts = summarise(
        [
            Finding(code="A", level=Level.ERROR, message=""),
            Finding(code="B", level=Level.WARNING, message=""),
            Finding(code="C", level=Level.WARNING, message=""),
        ]
    )
    assert counts == {"error": 1, "warning": 2, "info": 0, "total": 3}


# --------------------------------------------------------------- scorecard


def test_a_good_rule_scores_well(context):
    scoring = ScoringContext(
        catalog=context.catalog,
        known_tests=context.known_tests,
        attack=context.attack,
        outcomes={"good_rule": Outcome.DETECTED},
    )
    score = score_rule(Rule.from_dict(GOOD), scoring)
    assert score.total >= 80
    assert score.grade in ("A", "B")


def test_an_unvalidated_rule_scores_zero_on_validation():
    document = {k: v for k, v in GOOD.items() if k != "validation"}
    score = score_rule(Rule.from_dict(document), ScoringContext())
    validation = next(d for d in score.dimensions if d.name == "validation")
    assert validation.score == 0.0


def test_proof_outweighs_polish():
    # A beautifully documented rule that has never fired must score below a
    # terse one that demonstrably works.
    documented = {k: v for k, v in GOOD.items() if k != "validation"}
    terse = {
        "name": "terse",
        "title": "Terse",
        "telemetry": ["sysmon_process_creation"],
        "attack": ["T1059.001"],
        "detection": GOOD["detection"],
        "validation": GOOD["validation"],
    }
    scoring = ScoringContext(outcomes={"terse": Outcome.DETECTED})
    assert (
        score_rule(Rule.from_dict(terse), scoring).total
        > score_rule(Rule.from_dict(documented), ScoringContext()).total
    )


def test_a_blind_outcome_hurts_more_than_a_visible_one():
    visible = ScoringContext(outcomes={"good_rule": Outcome.VISIBLE})
    blind = ScoringContext(outcomes={"good_rule": Outcome.BLIND})
    rule = Rule.from_dict(GOOD)
    assert score_rule(rule, blind).total < score_rule(rule, visible).total


def test_noise_is_penalised():
    quiet = ScoringContext(outcomes={"good_rule": Outcome.DETECTED})
    noisy = ScoringContext(outcomes={"good_rule": Outcome.DETECTED}, noisy=frozenset({"good_rule"}))
    rule = Rule.from_dict(GOOD)
    assert score_rule(rule, noisy).total < score_rule(rule, quiet).total


def test_accepted_gap_caps_the_validation_dimension():
    document = {
        **GOOD,
        "validation": {
            "emulation": ["T1059.001-powershell-encoded"],
            "expect": "blind",
            "justification": "not onboarded",
            "owner": "endpoint",
        },
    }
    score = score_rule(Rule.from_dict(document), ScoringContext())
    validation = next(d for d in score.dimensions if d.name == "validation")
    assert validation.score <= 50


def test_weakest_dimension_is_identified():
    document = {k: v for k, v in GOOD.items() if k != "telemetry"}
    score = score_rule(Rule.from_dict(document), ScoringContext())
    assert score.weakest.name in ("telemetry", "validation")


def test_library_rollup(workspace):
    from rulekit.scorecard import score_library

    library = score_library(workspace.rules, ScoringContext(catalog=workspace.telemetry))
    assert len(library.rules) == len(workspace.rules)
    assert 0 <= library.average <= 100
    assert sum(library.distribution().values()) == len(library.rules)
    assert set(library.by_dimension()) == {
        "validation",
        "robustness",
        "telemetry",
        "attack",
        "documentation",
        "hygiene",
    }
