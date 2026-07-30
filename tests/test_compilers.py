"""Query compilation across dialects."""

from __future__ import annotations

import pytest

from harness.core.errors import CompileError
from harness.core.models import Event
from rulekit.compilers import get_compiler
from rulekit.rule import Rule
from rulekit.telemetry import TelemetryCatalog

CATALOG_SOURCES = {
    "sysmon_process_creation": {
        "name": "Sysmon 1",
        "platform": "windows",
        "fields": ["EventID", "Image", "CommandLine", "ParentImage"],
        "backends": {
            "splunk": {"scope": "index=windows EventCode=1"},
            "elastic": {"scope": 'event.code:"1"'},
            "sentinel": {"table": "SysmonEvent", "scope": "EventID == 1"},
            "fixture": {"scope": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}},
        },
    },
    "no_sentinel_mapping": {
        "name": "Unmapped",
        "platform": "windows",
        "backends": {"splunk": {"scope": "index=other"}},
    },
}


@pytest.fixture
def catalog() -> TelemetryCatalog:
    from rulekit.telemetry import TelemetrySource

    return TelemetryCatalog(
        sources={
            key: TelemetrySource.from_dict(key, value) for key, value in CATALOG_SOURCES.items()
        }
    )


def build_rule(**overrides) -> Rule:
    document = {
        "title": "Test rule",
        "name": "test_rule",
        "telemetry": ["sysmon_process_creation"],
        "detection": {
            "selection": {
                "EventID": 1,
                "Image|endswith": "\\rundll32.exe",
                "CommandLine|contains": "javascript:",
            },
            "filter_known_good": {"ParentImage|endswith": "\\ccmexec.exe"},
            "condition": "selection and not filter_known_good",
        },
    }
    document.update(overrides)
    return Rule.from_dict(document)


# ---------------------------------------------------------------- structure


@pytest.mark.parametrize("dialect", ["splunk", "elastic", "sentinel"])
def test_every_dialect_preserves_the_negation(catalog, dialect):
    # A compiler that silently drops `not filter` produces a rule that looks
    # fine and alerts on everything. This is the regression that matters most.
    query = get_compiler(dialect, catalog).compile(build_rule())
    lowered = query.text.lower()
    assert "not" in lowered
    assert "ccmexec.exe" in query.text


@pytest.mark.parametrize("dialect", ["splunk", "elastic", "sentinel"])
def test_scope_is_prefixed_from_the_telemetry_catalogue(catalog, dialect):
    query = get_compiler(dialect, catalog).compile(build_rule())
    expected = CATALOG_SOURCES["sysmon_process_creation"]["backends"][dialect]["scope"]
    assert expected in query.text


@pytest.mark.parametrize("dialect", ["splunk", "elastic", "sentinel"])
def test_telemetry_probe_omits_detection_logic(catalog, dialect):
    probe = get_compiler(dialect, catalog).compile_telemetry(build_rule())
    assert probe is not None
    # The probe answers "did the data arrive", so none of the rule's own
    # matching may leak into it.
    assert "javascript" not in probe.text
    assert "rundll32" not in probe.text


def test_no_probe_without_a_telemetry_declaration(catalog):
    rule = build_rule(telemetry=[])
    assert get_compiler("splunk", catalog).compile_telemetry(rule) is None


# ------------------------------------------------------------------ splunk


def test_splunk_uses_search_syntax_when_it_can(catalog):
    query = get_compiler("splunk", catalog).compile(build_rule())
    assert query.metadata["mode"] == "search"
    assert "| where" not in query.text
    assert 'Image="*\\\\rundll32.exe"' in query.text


def test_splunk_switches_to_where_for_regex(catalog):
    rule = build_rule(
        detection={
            "selection": {"CommandLine|re": "curl.*\\|.*sh"},
            "condition": "selection",
        }
    )
    query = get_compiler("splunk", catalog).compile(rule)
    assert query.metadata["mode"] == "where"
    assert "| where" in query.text
    assert "match(" in query.text


def test_splunk_exists_uses_search_idiom_not_eval(catalog):
    rule = build_rule(detection={"selection": {"errorCode|exists": True}, "condition": "selection"})
    text = get_compiler("splunk", catalog).compile(rule).text
    # isnotnull() is an eval function and is invalid in search mode.
    assert "errorCode=*" in text
    assert "isnotnull" not in text


# ----------------------------------------------------------------- elastic


def test_elastic_quotes_plain_values_and_leaves_wildcards_bare(catalog):
    text = get_compiler("elastic", catalog).compile(build_rule()).text
    # `|endswith` and `|contains` introduce wildcards, which are inert inside a
    # quoted phrase - so those clauses must be escaped term-wise, unquoted.
    assert "Image:*\\\\rundll32.exe" in text
    assert "CommandLine:*javascript\\:*" in text
    # A plain equality value has no wildcards and is quoted.
    assert 'EventID:"1"' in text


def test_elastic_renders_numeric_ranges(catalog):
    rule = build_rule(detection={"selection": {"Count|gte": 5}, "condition": "selection"})
    assert "Count:[5.0 TO *]" in get_compiler("elastic", catalog).compile(rule).text


# --------------------------------------------------------------------- kql


def test_kql_targets_the_declared_table(catalog):
    text = get_compiler("sentinel", catalog).compile(build_rule()).text
    assert text.startswith("SysmonEvent")
    assert "| where" in text


def test_kql_keeps_numeric_fields_numeric(catalog):
    # Kusto is strongly typed: `EventID =~ "1"` on an int column is an error.
    text = get_compiler("sentinel", catalog).compile(build_rule()).text
    assert "EventID == 1" in text
    assert 'EventID =~ "1"' not in text


def test_kql_refuses_a_rule_spanning_two_tables(catalog):
    from rulekit.telemetry import TelemetrySource

    catalog.sources["other_table"] = TelemetrySource.from_dict(
        "other_table",
        {"name": "Other", "backends": {"sentinel": {"table": "SecurityEvent", "scope": "1==1"}}},
    )
    rule = build_rule(telemetry=["sysmon_process_creation", "other_table"])
    with pytest.raises(CompileError, match="multiple KQL tables"):
        get_compiler("sentinel", catalog).compile(rule)


def test_kql_refuses_a_rule_with_no_table(catalog):
    rule = build_rule(telemetry=["no_sentinel_mapping"])
    with pytest.raises(CompileError, match="no KQL table"):
        get_compiler("sentinel", catalog).compile(rule)


# ------------------------------------------------------------------ fixture


def test_fixture_compiles_to_a_callable_predicate(catalog):
    query = get_compiler("fixture", catalog).compile(build_rule())
    assert callable(query.payload)


def test_fixture_predicate_matches_a_true_positive(catalog):
    predicate = get_compiler("fixture", catalog).compile(build_rule()).payload
    assert predicate(
        Event(
            raw={
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";',
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            }
        )
    )


def test_fixture_predicate_honours_the_exclusion(catalog):
    predicate = get_compiler("fixture", catalog).compile(build_rule()).payload
    assert not predicate(
        Event(
            raw={
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe javascript:whatever",
                "ParentImage": "C:\\Windows\\CCM\\ccmexec.exe",
            }
        )
    )


def test_fixture_scope_excludes_the_wrong_channel(catalog):
    predicate = get_compiler("fixture", catalog).compile(build_rule()).payload
    assert not predicate(
        Event(
            raw={
                "Channel": "Security",
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe javascript:whatever",
            }
        )
    )


# -------------------------------------------------------------- registry


def test_dialect_aliases_resolve_to_the_canonical_compiler(catalog):
    # opensearch shares Elastic's mapping key, so a rule must not lose its scope
    # just because the backend was configured under the alias.
    assert get_compiler("opensearch", catalog).dialect == "elastic"
    assert get_compiler("defender", catalog).dialect == "sentinel"


def test_unknown_dialect_is_rejected(catalog):
    with pytest.raises(CompileError, match="no compiler for dialect"):
        get_compiler("nonesuch", catalog)
