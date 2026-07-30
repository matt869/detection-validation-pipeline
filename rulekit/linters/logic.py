"""Detection-logic checks.

These catch the failure modes that make a rule *look* fine in review and behave
badly in production: dead selections, filters that match everything, and
literals so short they will fire on unrelated traffic.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from harness.core.models import RuleStatus
from rulekit.linters.base import Finding, Level, LintContext, Linter, iter_selections
from rulekit.matcher import parse_field_spec
from rulekit.rule import Rule

#: Literals shorter than this used with |contains fire on unrelated data.
_MIN_CONTAINS_LENGTH = 4
#: Above this, a rule is hard to reason about in review.
_MAX_SELECTIONS = 12
#: Regex constructs prone to catastrophic backtracking.
_REDOS = re.compile(r"\((?:[^()]*[+*])\)[+*]|\(\?:[^()]*[+*]\)[+*]")

#: Names conventionally used for exclusion selections.
_FILTER_PREFIXES = ("filter", "exclude", "known_good", "allowlist", "whitelist")


class LogicLinter(Linter):
    category = "logic"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        yield from self._dead_logic(rule)
        yield from self._breadth(rule)
        yield from self._values(rule)
        yield from self._complexity(rule)

    def _dead_logic(self, rule: Rule) -> Iterable[Finding]:
        for name in rule.unused_selections:
            yield self.finding(
                rule,
                "LG001",
                Level.ERROR,
                f"selection '{name}' is defined but never used in the condition",
                hint="Either reference it or delete it - as written it has no effect.",
                locator=f"detection.{name}",
            )

    def _breadth(self, rule: Rule) -> Iterable[Finding]:
        for name, selection in iter_selections(rule):
            if _matches_everything(selection):
                yield self.finding(
                    rule,
                    "LG002",
                    Level.ERROR,
                    f"selection '{name}' matches every event",
                    hint="A bare '*' value disables the filter it appears in.",
                    locator=f"detection.{name}",
                )

        has_filter = any(
            name.lower().startswith(_FILTER_PREFIXES) for name, _ in iter_selections(rule)
        )
        if rule.status is RuleStatus.PRODUCTION and not has_filter:
            yield self.finding(
                rule,
                "LG003",
                Level.INFO,
                "no exclusion selection - there is nowhere to hang environment tuning",
                hint="Add a 'filter_known_good' selection now, even if empty of "
                "entries, so tuning does not have to edit detection logic later.",
                locator="detection",
            )

    def _values(self, rule: Rule) -> Iterable[Finding]:
        for name, selection in iter_selections(rule):
            for key, value in _iter_pairs(selection):
                spec = parse_field_spec(key)
                values = value if isinstance(value, list) else [value]

                if spec.comparison == "contains":
                    for item in values:
                        text = str(item or "")
                        if 0 < len(text.strip()) < _MIN_CONTAINS_LENGTH:
                            yield self.finding(
                                rule,
                                "LG004",
                                Level.WARNING,
                                f"'{key}|contains: {item!r}' is only "
                                f"{len(text.strip())} characters - expect false positives",
                                locator=f"detection.{name}.{key}",
                            )

                if spec.comparison == "re":
                    for item in values:
                        pattern = str(item)
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            yield self.finding(
                                rule,
                                "LG005",
                                Level.ERROR,
                                f"invalid regular expression in '{key}': {exc}",
                                locator=f"detection.{name}.{key}",
                            )
                            continue
                        if _REDOS.search(pattern):
                            yield self.finding(
                                rule,
                                "LG006",
                                Level.WARNING,
                                f"nested quantifier in '{key}' regex may backtrack "
                                "catastrophically on long inputs",
                                hint="Rewrite the inner group to be possessive or "
                                "anchor the pattern.",
                                locator=f"detection.{name}.{key}",
                            )

                if isinstance(value, list):
                    lowered = [str(v).casefold() for v in value]
                    duplicates = {v for v in lowered if lowered.count(v) > 1}
                    if duplicates:
                        yield self.finding(
                            rule,
                            "LG007",
                            Level.INFO,
                            f"'{key}' repeats value(s): {', '.join(sorted(duplicates))}",
                            locator=f"detection.{name}.{key}",
                        )

    def _complexity(self, rule: Rule) -> Iterable[Finding]:
        count = len(rule.selections)
        if count > _MAX_SELECTIONS:
            yield self.finding(
                rule,
                "LG008",
                Level.INFO,
                f"{count} selections - consider splitting into focused rules",
                hint="Large rules are hard to tune: one noisy branch forces "
                "suppression of the whole alert.",
                locator="detection",
            )

        # A single-field equality rule is trivially evaded; flag it in production.
        if rule.status is RuleStatus.PRODUCTION and len(rule.field_names) == 1:
            yield self.finding(
                rule,
                "LG009",
                Level.WARNING,
                f"rule depends on a single field ({rule.field_names[0]})",
                hint="Single-indicator rules break the moment the attacker renames "
                "one thing. Corroborate with a second field.",
                locator="detection",
            )


def _matches_everything(selection: Any) -> bool:
    """True if a selection imposes no constraint at all."""
    if isinstance(selection, dict):
        if not selection:
            return True
        return all(_value_matches_everything(v) for v in selection.values())
    if isinstance(selection, list):
        return bool(selection) and any(_matches_everything(item) for item in selection)
    return str(selection).strip() == "*"


def _value_matches_everything(value: Any) -> bool:
    if isinstance(value, list):
        return bool(value) and any(_value_matches_everything(v) for v in value)
    return str(value).strip() in ("*", "**")


def _iter_pairs(selection: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(selection, dict):
        yield from ((str(k), v) for k, v in selection.items())
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                yield from ((str(k), v) for k, v in item.items())
