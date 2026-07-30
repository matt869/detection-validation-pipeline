"""Scoring logic.

Six weighted dimensions. The weights encode an opinion worth stating plainly:
**proof outweighs polish**. A beautifully documented rule that has never been
shown to fire scores worse than a terse one that demonstrably catches its
technique on every run.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from harness.core.models import Outcome, RuleStatus
from rulekit.library import RuleLibrary
from rulekit.matcher import parse_field_spec
from rulekit.rule import Rule
from rulekit.scorecard.model import DimensionScore, LibraryScore, RuleScore
from rulekit.telemetry import TelemetryCatalog

__all__ = ["ScoringContext", "score_library", "score_rule"]

WEIGHTS = {
    "validation": 0.28,
    "robustness": 0.20,
    "telemetry": 0.16,
    "attack": 0.14,
    "documentation": 0.12,
    "hygiene": 0.10,
}

#: Fields whose value an attacker changes trivially. A rule resting entirely on
#: one of these is brittle even when it is currently effective.
_BRITTLE_FIELDS = {
    "image",
    "originalfilename",
    "parentimage",
    "filename",
    "processname",
    "targetfilename",
}
_FILTER_PREFIXES = ("filter", "exclude", "known_good", "allowlist", "whitelist")


@dataclass(slots=True)
class ScoringContext:
    """Evidence available to the scorer beyond the rule text itself."""

    catalog: TelemetryCatalog = field(default_factory=TelemetryCatalog.empty)
    known_tests: frozenset[str] = frozenset()
    attack: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    required_dialects: tuple[str, ...] = ()
    #: rule name -> outcome from the most recent validation run.
    outcomes: Mapping[str, Outcome] = field(default_factory=dict)
    #: Rules that matched activity in a quiet baseline window.
    noisy: frozenset[str] = frozenset()
    #: rule name -> observed detection latency in seconds.
    latencies: Mapping[str, float] = field(default_factory=dict)

    def technique_lookup(self, technique_id: str) -> Mapping[str, Any] | None:
        """Resolve a technique, falling back to its parent for sub-techniques."""
        entry = self.attack.get(technique_id)
        if entry is None and "." in technique_id:
            return self.attack.get(technique_id.split(".", 1)[0])
        return entry


def score_rule(rule: Rule, context: ScoringContext | None = None) -> RuleScore:
    context = context or ScoringContext()
    return RuleScore(
        rule_name=rule.name,
        title=rule.title,
        severity=rule.severity.value,
        status=rule.status.value,
        techniques=tuple(t for t in rule.technique_ids if t),
        dimensions=(
            _score_validation(rule, context),
            _score_robustness(rule, context),
            _score_telemetry(rule, context),
            _score_attack(rule, context),
            _score_documentation(rule, context),
            _score_hygiene(rule, context),
        ),
    )


def score_library(library: RuleLibrary, context: ScoringContext | None = None) -> LibraryScore:
    context = context or ScoringContext(catalog=library.catalog)
    return LibraryScore(rules=[score_rule(rule, context) for rule in library])


# ------------------------------------------------------------------ dimensions


def _score_validation(rule: Rule, context: ScoringContext) -> DimensionScore:
    """Has this rule been *shown* to work, recently, and fast enough?"""
    deductions: list[str] = []
    score = 100.0
    spec = rule.validation

    if not spec.emulation:
        return DimensionScore(
            name="validation",
            score=0.0,
            weight=WEIGHTS["validation"],
            deductions=("no emulation test - the rule is an untested claim",),
            rationale="Proof the rule fires on the behaviour it targets.",
        )

    if context.known_tests:
        missing = [t for t in spec.emulation if t not in context.known_tests]
        if missing:
            score -= 40
            deductions.append(f"emulation test(s) not found: {', '.join(missing)}")

    if not spec.enabled:
        score -= 30
        deductions.append("validation is disabled")

    outcome = context.outcomes.get(rule.name)
    if outcome is None:
        score -= 25
        deductions.append("no result from any recorded run")
    elif outcome is Outcome.DETECTED:
        latency = context.latencies.get(rule.name)
        if latency is not None and latency > spec.max_latency_seconds:
            score -= 15
            deductions.append(
                f"detected, but in {latency:.0f}s against a {spec.max_latency_seconds:.0f}s budget"
            )
    elif outcome is Outcome.VISIBLE:
        score -= 55
        deductions.append("telemetry arrived but the rule did not fire (detection gap)")
    elif outcome is Outcome.BLIND:
        score -= 70
        deductions.append("required telemetry never arrived (visibility gap)")
    elif outcome is Outcome.ERROR:
        score -= 20
        deductions.append("last run errored")

    if spec.expect is not Outcome.DETECTED:
        # A documented gap is honest, but it is still a gap.
        score = min(score, 50.0)
        deductions.append(f"expectation is '{spec.expect.value}', an accepted gap")

    return DimensionScore(
        name="validation",
        score=_clamp(score),
        weight=WEIGHTS["validation"],
        deductions=tuple(deductions),
        rationale="Proof the rule fires on the behaviour it targets.",
    )


def _score_robustness(rule: Rule, context: ScoringContext) -> DimensionScore:
    """How hard is this rule to evade with a trivial change?"""
    deductions: list[str] = []
    score = 100.0
    fields = [f.casefold() for f in rule.field_names]

    if not fields:
        return DimensionScore(
            name="robustness",
            score=0.0,
            weight=WEIGHTS["robustness"],
            deductions=("keyword-only rule with no field constraints",),
            rationale="Resistance to trivial attacker evasion.",
        )

    if len(fields) == 1:
        score -= 35
        deductions.append(f"single-field rule ({rule.field_names[0]})")
        if fields[0] in _BRITTLE_FIELDS:
            score -= 15
            deductions.append(f"{rule.field_names[0]} is renamed trivially")
    elif len(set(fields)) == 2:
        score -= 10
        deductions.append("only two distinct fields")

    if set(fields).issubset(_BRITTLE_FIELDS):
        score -= 20
        deductions.append("every field is an easily-changed name or path")

    has_filter = any(name.lower().startswith(_FILTER_PREFIXES) for name in rule.selections)
    if not has_filter:
        score -= 10
        deductions.append("no exclusion selection for environment tuning")

    # Exact-equality on a full path is more brittle than a suffix or a
    # command-line substring, which survives relocation of the binary.
    exact_paths = 0
    for name, selection in rule.detection.items():
        if name == "condition" or not isinstance(selection, dict):
            continue
        for key, value in selection.items():
            spec = parse_field_spec(str(key))
            if spec.comparison == "equals" and spec.field.casefold() in _BRITTLE_FIELDS:
                values = value if isinstance(value, list) else [value]
                if any("\\" in str(v) or "/" in str(v) for v in values):
                    exact_paths += 1
    if exact_paths:
        score -= min(15, 5 * exact_paths)
        deductions.append(f"{exact_paths} exact full-path match(es); prefer |endswith")

    if rule.status is RuleStatus.PRODUCTION and not rule.falsepositives:
        score -= 5
        deductions.append("no false-positive analysis recorded")

    return DimensionScore(
        name="robustness",
        score=_clamp(score),
        weight=WEIGHTS["robustness"],
        deductions=tuple(deductions),
        rationale="Resistance to trivial attacker evasion.",
    )


def _score_telemetry(rule: Rule, context: ScoringContext) -> DimensionScore:
    deductions: list[str] = []
    score = 100.0

    if not rule.telemetry:
        return DimensionScore(
            name="telemetry",
            score=0.0,
            weight=WEIGHTS["telemetry"],
            deductions=("no telemetry sources declared",),
            rationale="Whether the rule's data dependency is known and mapped.",
        )

    for source_id in rule.telemetry:
        source = context.catalog.get(source_id)
        if source is None:
            score -= 40
            deductions.append(f"unknown telemetry source '{source_id}'")
            continue
        if not source.owner:
            score -= 5
            deductions.append(f"'{source_id}' has no owner")
        for dialect in context.required_dialects:
            if not source.supports(dialect):
                score -= 15
                deductions.append(f"'{source_id}' has no '{dialect}' mapping")

    return DimensionScore(
        name="telemetry",
        score=_clamp(score),
        weight=WEIGHTS["telemetry"],
        deductions=tuple(deductions),
        rationale="Whether the rule's data dependency is known and mapped.",
    )


def _score_attack(rule: Rule, context: ScoringContext) -> DimensionScore:
    deductions: list[str] = []
    techniques = [t for t in rule.technique_ids if t]

    if not techniques:
        return DimensionScore(
            name="attack",
            score=0.0,
            weight=WEIGHTS["attack"],
            deductions=("no ATT&CK mapping",),
            rationale="Placement on the coverage map.",
        )

    score = 100.0
    if not rule.tactics:
        score -= 20
        deductions.append("no tactic - kill-chain reporting will be incomplete")

    if context.attack:
        unknown = [t for t in techniques if context.technique_lookup(t) is None]
        if unknown:
            score -= 25
            deductions.append(f"unmapped technique(s): {', '.join(unknown)}")

    parents_with_children = [
        t for t in techniques if "." not in t and (context.attack.get(t) or {}).get("subtechniques")
    ]
    if parents_with_children:
        score -= 15
        deductions.append(
            f"maps to parent technique(s) {', '.join(parents_with_children)} that have "
            "sub-techniques; coverage is over-stated"
        )

    return DimensionScore(
        name="attack",
        score=_clamp(score),
        weight=WEIGHTS["attack"],
        deductions=tuple(deductions),
        rationale="Placement on the coverage map.",
    )


def _score_documentation(rule: Rule, context: ScoringContext) -> DimensionScore:
    deductions: list[str] = []
    score = 100.0

    if not rule.description:
        score -= 35
        deductions.append("no description")
    elif len(rule.description) < 40:
        score -= 15
        deductions.append("description too short to triage against")

    if not rule.references:
        score -= 20
        deductions.append("no references")
    if not rule.author:
        score -= 15
        deductions.append("no author")
    if not rule.falsepositives:
        score -= 15
        deductions.append("no known false positives listed")
    if not rule.fields:
        score -= 10
        deductions.append("no 'fields' list - the alert will not surface useful context")
    if not rule.date:
        score -= 5
        deductions.append("no date")

    return DimensionScore(
        name="documentation",
        score=_clamp(score),
        weight=WEIGHTS["documentation"],
        deductions=tuple(deductions),
        rationale="Whether a responder who has never seen this rule can act on it.",
    )


def _score_hygiene(rule: Rule, context: ScoringContext) -> DimensionScore:
    deductions: list[str] = []
    score = 100.0

    if not rule.id:
        score -= 25
        deductions.append("no stable id")
    if rule.unused_selections:
        score -= 25
        deductions.append(f"dead selection(s): {', '.join(rule.unused_selections)}")
    if rule.unknown_keys:
        score -= 10
        deductions.append(f"unrecognised key(s): {', '.join(rule.unknown_keys)}")
    if rule.name in context.noisy:
        score -= 40
        deductions.append("fires on quiet-baseline activity")
    if rule.status is RuleStatus.EXPERIMENTAL:
        score -= 10
        deductions.append("still experimental")
    elif rule.status in (RuleStatus.DEPRECATED, RuleStatus.UNSUPPORTED):
        score -= 30
        deductions.append(f"status is {rule.status.value}")

    return DimensionScore(
        name="hygiene",
        score=_clamp(score),
        weight=WEIGHTS["hygiene"],
        deductions=tuple(deductions),
        rationale="Housekeeping: identity, dead logic, and alert noise.",
    )


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))
