"""Field matching semantics.

This is the reference implementation of what a rule *means*, so a regression
here silently changes the behaviour of every compiled query. Tested closely.
"""

from __future__ import annotations

import pytest

from harness.core.models import Event
from rulekit.matcher import (
    MatchError,
    build_selection_predicate,
    expand_values,
    parse_field_spec,
)


def event(**fields) -> Event:
    return Event(raw=dict(fields))


def matches(selection, **fields) -> bool:
    return build_selection_predicate(selection)(event(**fields))


# ------------------------------------------------------------- spec parsing


def test_parse_plain_field():
    spec = parse_field_spec("CommandLine")
    assert spec.field == "CommandLine"
    assert spec.comparison == "equals"
    assert not spec.require_all


def test_parse_modifiers():
    spec = parse_field_spec("CommandLine|contains|all")
    assert spec.field == "CommandLine"
    assert spec.comparison == "contains"
    assert spec.require_all


def test_unknown_modifier_is_rejected():
    with pytest.raises(MatchError, match="unknown modifier"):
        parse_field_spec("Image|endswith|typo")


def test_conflicting_comparisons_are_rejected():
    with pytest.raises(MatchError, match="conflict"):
        parse_field_spec("Image|contains|endswith")


# ---------------------------------------------------------------- equality


def test_equality_is_case_insensitive_by_default():
    assert matches({"Image": "CMD.EXE"}, Image="cmd.exe")


def test_cased_modifier_restores_exact_comparison():
    assert not matches({"Image|cased": "CMD.EXE"}, Image="cmd.exe")
    assert matches({"Image|cased": "cmd.exe"}, Image="cmd.exe")


def test_numeric_literal_matches_string_field():
    # Backends return EventID as a string about half the time.
    assert matches({"EventID": 10}, EventID="10")
    assert matches({"EventID": 10}, EventID=10)


def test_list_value_is_an_or():
    assert matches({"EventID": [1, 3, 10]}, EventID=3)
    assert not matches({"EventID": [1, 3, 10]}, EventID=5)


def test_all_modifier_turns_a_list_into_an_and():
    selection = {"CommandLine|contains|all": ["process", "call", "create"]}
    assert matches(selection, CommandLine="wmic process call create foo")
    assert not matches(selection, CommandLine="wmic process list")


def test_dict_keys_are_anded():
    selection = {"EventID": 1, "Image|endswith": "\\reg.exe"}
    assert matches(selection, EventID=1, Image="C:\\Windows\\System32\\reg.exe")
    assert not matches(selection, EventID=1, Image="C:\\Windows\\System32\\cmd.exe")


def test_list_of_dicts_is_an_or():
    selection = [{"ServiceName|contains": "PSEXESVC"}, {"ImagePath|contains": "%COMSPEC%"}]
    assert matches(selection, ImagePath="%COMSPEC% /c exit 0")
    assert matches(selection, ServiceName="PSEXESVC")
    assert not matches(selection, ServiceName="gupdate", ImagePath="C:\\x.exe")


# -------------------------------------------------------------- substrings


@pytest.mark.parametrize(
    ("modifier", "value", "field", "expected"),
    [
        ("contains", "lsass", "C:\\Windows\\lsass.exe", True),
        ("contains", "lsass", "C:\\Windows\\cmd.exe", False),
        ("startswith", "C:\\Windows", "C:\\Windows\\lsass.exe", True),
        ("startswith", "lsass", "C:\\Windows\\lsass.exe", False),
        ("endswith", "\\lsass.exe", "C:\\Windows\\lsass.exe", True),
        ("endswith", "lsass", "C:\\Windows\\lsass.exe", False),
    ],
)
def test_substring_modifiers(modifier, value, field, expected):
    assert matches({f"Image|{modifier}": value}, Image=field) is expected


# --------------------------------------------------------------- wildcards


def test_wildcard_in_a_plain_value():
    assert matches({"Image": "*\\lsass.exe"}, Image="C:\\Windows\\lsass.exe")
    assert not matches({"Image": "*\\lsass.exe"}, Image="C:\\Windows\\cmd.exe")


def test_question_mark_matches_one_character():
    assert matches({"Name": "abc?ef"}, Name="abcdef")
    assert not matches({"Name": "abc?ef"}, Name="abcef")


def test_escaped_wildcard_is_literal():
    assert matches({"Name": "literal\\*star"}, Name="literal*star")
    assert not matches({"Name": "literal\\*star"}, Name="literalXstar")


def test_backslash_escape_resolves_to_one_backslash():
    # Sigma convention: `\\` in a rule value means one literal backslash.
    assert matches({"Image|contains": r"\\"}, Image=r"C:\Windows\cmd.exe")


def test_unc_prefix_needs_four_backslashes_in_the_rule():
    # Two literal backslashes to search for means four in the rule value - which
    # is exactly what the shipped rules write as '\\\\' in single-quoted YAML.
    selection = {"CommandLine|contains": r"\\\\"}
    assert matches(selection, CommandLine=r"rundll32 \\fileserver\share\a.dll")
    assert not matches(selection, CommandLine=r"rundll32 C:\Windows\a.dll")


# ------------------------------------------------------------------ regex


def test_regex_modifier():
    selection = {"cmdline|re": r"(curl|wget)\s[^|]*\|\s*(ba)?sh\b"}
    assert matches(selection, cmdline="curl -s https://x/i.sh | bash")
    assert not matches(selection, cmdline="curl -s https://x/i.sh -o /tmp/i.sh")


def test_invalid_regex_is_rejected_at_build_time():
    with pytest.raises(MatchError, match="invalid regular expression"):
        build_selection_predicate({"cmdline|re": "([unclosed"})


# ------------------------------------------------------------------- cidr


def test_cidr_membership():
    assert matches({"IpAddress|cidr": "10.0.0.0/8"}, IpAddress="10.10.5.44")
    assert not matches({"IpAddress|cidr": "10.0.0.0/8"}, IpAddress="192.168.1.1")


def test_cidr_ignores_unparsable_addresses():
    assert not matches({"IpAddress|cidr": "10.0.0.0/8"}, IpAddress="-")


# -------------------------------------------------------------- numeric


@pytest.mark.parametrize(
    ("modifier", "threshold", "value", "expected"),
    [
        ("gt", 5, 6, True),
        ("gt", 5, 5, False),
        ("gte", 5, 5, True),
        ("lt", 5, 4, True),
        ("lte", 5, 5, True),
    ],
)
def test_numeric_comparisons(modifier, threshold, value, expected):
    assert matches({f"Count|{modifier}": threshold}, Count=value) is expected


def test_hex_strings_compare_numerically():
    assert matches({"Access|gte": 16}, Access="0x10")


# ------------------------------------------------------------ null/exists


def test_null_matches_absent_field():
    assert matches({"ErrorCode": None}, EventID=1)
    assert not matches({"ErrorCode": None}, ErrorCode="AccessDenied")


def test_exists_modifier():
    assert matches({"errorCode|exists": True}, errorCode="AccessDenied")
    assert not matches({"errorCode|exists": True}, eventName="StopLogging")
    assert matches({"errorCode|exists": False}, eventName="StopLogging")


# ---------------------------------------------------------- transforms


def test_windash_expands_dash_variants():
    values = expand_values(parse_field_spec("CommandLine|contains|windash"), "-enc ")
    assert "/enc " in values
    assert "-enc " in values


def test_windash_matches_slash_spelling():
    selection = {"CommandLine|contains|windash": "-create"}
    assert matches(selection, CommandLine="schtasks /create /tn Foo")
    assert matches(selection, CommandLine="schtasks -create -tn Foo")


def test_base64offset_generates_three_alignments():
    values = expand_values(parse_field_spec("CommandLine|base64offset|contains"), "whoami")
    assert len(values) == 3
    assert len(set(values)) == 3


# ------------------------------------------------- field resolution on events


def test_dotted_path_resolution():
    nested = Event(raw={"userIdentity": {"type": "Root", "arn": "arn:aws:iam::1:root"}})
    assert nested.get("userIdentity.type") == "Root"


def test_case_insensitive_key_resolution():
    assert Event(raw={"EventID": 1}).get("eventid") == 1


def test_unique_leaf_name_resolution():
    # One Sigma rule has to work against both a flat Windows export and a
    # nested ECS document.
    nested = Event(raw={"process": {"command_line": "cmd.exe /c whoami"}})
    assert nested.get("command_line") == "cmd.exe /c whoami"


def test_ambiguous_leaf_name_resolves_to_nothing():
    ambiguous = Event(raw={"a": {"name": "x"}, "b": {"name": "y"}})
    assert ambiguous.get("name") is None


def test_multi_valued_field_matches_any_element():
    assert matches({"tags|contains": "lab"}, tags=["prod", "lab-west"])


# -------------------------------------------------------------- guardrails


def test_empty_selection_is_rejected():
    # An empty mapping would match every event and silently disable a filter.
    with pytest.raises(MatchError, match="would match every event"):
        build_selection_predicate({})


def test_empty_list_selection_is_rejected():
    with pytest.raises(MatchError, match="never match"):
        build_selection_predicate([])


def test_keyword_selection_searches_the_whole_event():
    assert matches(["dvp-validation-marker"], CommandLine="echo dvp-validation-marker")
