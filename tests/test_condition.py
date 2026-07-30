"""Condition grammar."""

from __future__ import annotations

import pytest

from rulekit.condition import And, ConditionError, Not, Or, Ref, parse_condition


def test_single_reference():
    assert parse_condition("selection", ["selection"]) == Ref("selection")


def test_and_or_precedence():
    # `a and b or c` must parse as `(a and b) or c`, not `a and (b or c)`.
    node = parse_condition("a and b or c", ["a", "b", "c"])
    assert isinstance(node, Or)
    assert node.nodes[0] == And((Ref("a"), Ref("b")))
    assert node.nodes[1] == Ref("c")


def test_parentheses_override_precedence():
    node = parse_condition("a and (b or c)", ["a", "b", "c"])
    assert isinstance(node, And)
    assert node.nodes[1] == Or((Ref("b"), Ref("c")))


def test_not_binds_tighter_than_and():
    node = parse_condition("a and not b", ["a", "b"])
    assert node == And((Ref("a"), Not(Ref("b"))))


def test_not_applies_to_parenthesised_group():
    node = parse_condition("a and not (b or c)", ["a", "b", "c"])
    assert node == And((Ref("a"), Not(Or((Ref("b"), Ref("c"))))))


def test_keywords_are_case_insensitive():
    assert parse_condition("a AND NOT b", ["a", "b"]) == parse_condition(
        "a and not b", ["a", "b"]
    )


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1 of sel*", Or((Ref("sel_a"), Ref("sel_b")))),
        ("all of sel*", And((Ref("sel_a"), Ref("sel_b")))),
    ],
)
def test_quantifiers_expand_at_parse_time(expression, expected):
    assert parse_condition(expression, ["sel_a", "sel_b", "filter_x"]) == expected


def test_quantifier_them_covers_every_selection():
    node = parse_condition("1 of them", ["a", "b", "c"])
    assert node == Or((Ref("a"), Ref("b"), Ref("c")))


def test_quantifier_over_single_match_collapses():
    assert parse_condition("all of sel*", ["sel_only"]) == Ref("sel_only")


def test_bare_glob_means_all_of():
    node = parse_condition("filter*", ["filter_a", "filter_b"])
    assert node == And((Ref("filter_a"), Ref("filter_b")))


def test_quantifier_combines_with_not():
    node = parse_condition("sel and not 1 of filter*", ["sel", "filter_a", "filter_b"])
    assert node == And((Ref("sel"), Not(Or((Ref("filter_a"), Ref("filter_b"))))))


def test_unknown_selection_is_rejected():
    with pytest.raises(ConditionError, match="unknown selection"):
        parse_condition("selection and nope", ["selection"])


def test_error_carries_a_position_for_the_caret():
    with pytest.raises(ConditionError) as excinfo:
        parse_condition("selection and nope", ["selection"])
    assert excinfo.value.position == 14
    assert "^" in excinfo.value.annotated()


def test_unbalanced_parenthesis_is_rejected():
    with pytest.raises(ConditionError, match=r"expected '\)'"):
        parse_condition("(a and b", ["a", "b"])


def test_empty_condition_is_rejected():
    with pytest.raises(ConditionError, match="empty"):
        parse_condition("   ", ["a"])


def test_glob_matching_nothing_is_rejected():
    with pytest.raises(ConditionError, match="matches no selection"):
        parse_condition("1 of missing*", ["selection"])


def test_counting_quantifier_is_rejected_with_a_reason():
    # `2 of` cannot be expressed in most query languages; failing loudly beats
    # emitting a query that means something else.
    with pytest.raises(ConditionError, match="not supported"):
        parse_condition("2 of sel*", ["sel_a", "sel_b", "sel_c"])


def test_aggregation_pipe_is_rejected():
    with pytest.raises(ConditionError, match="aggregation"):
        parse_condition("selection | count() > 5", ["selection"])


def test_referenced_selections_reports_dependencies():
    from rulekit.condition import referenced_selections

    node = parse_condition("a and not (b or c)", ["a", "b", "c", "unused"])
    assert referenced_selections(node) == {"a", "b", "c"}
