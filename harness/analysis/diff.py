"""Run-over-run comparison.

A single run tells you the state of the world. Two runs tell you whether
somebody broke something, which is the question CI actually needs answered.

The comparison is per *case* (rule + emulation test), not per rule, because a
rule can legitimately detect one variant of a technique and not another; rolling
those together would hide the regression that matters.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from harness.analysis.classify import outcome_rank
from harness.core.models import CaseResult, Outcome, RunRecord

__all__ = ["CaseDelta", "DeltaKind", "RunDiff", "diff_runs"]


class DeltaKind(str, Enum):
    REGRESSION = "regression"
    IMPROVEMENT = "improvement"
    NEW = "new"
    REMOVED = "removed"
    UNCHANGED = "unchanged"
    #: Same outcome, but the detection got materially slower.
    SLOWER = "slower"


@dataclass(frozen=True, slots=True)
class CaseDelta:
    key: str
    rule_name: str
    emulation_id: str
    kind: DeltaKind
    before: Outcome | None
    after: Outcome | None
    before_latency: float | None = None
    after_latency: float | None = None
    severity: str = "medium"
    note: str = ""

    @property
    def is_regression(self) -> bool:
        return self.kind is DeltaKind.REGRESSION

    def describe(self) -> str:
        before = self.before.value if self.before else "-"
        after = self.after.value if self.after else "-"
        return f"{self.rule_name} / {self.emulation_id}: {before} -> {after}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "rule": self.rule_name,
            "emulation": self.emulation_id,
            "kind": self.kind.value,
            "before": self.before.value if self.before else None,
            "after": self.after.value if self.after else None,
            "before_latency": self.before_latency,
            "after_latency": self.after_latency,
            "severity": self.severity,
            "note": self.note,
        }


@dataclass(slots=True)
class RunDiff:
    baseline_run_id: str | None = None
    current_run_id: str = ""
    deltas: list[CaseDelta] = field(default_factory=list)

    def of_kind(self, kind: DeltaKind) -> list[CaseDelta]:
        return [d for d in self.deltas if d.kind is kind]

    @property
    def regressions(self) -> list[CaseDelta]:
        return self.of_kind(DeltaKind.REGRESSION)

    @property
    def improvements(self) -> list[CaseDelta]:
        return self.of_kind(DeltaKind.IMPROVEMENT)

    @property
    def changed(self) -> list[CaseDelta]:
        return [d for d in self.deltas if d.kind is not DeltaKind.UNCHANGED]

    def summary(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in DeltaKind}
        for delta in self.deltas:
            counts[delta.kind.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_run_id": self.baseline_run_id,
            "current_run_id": self.current_run_id,
            "summary": self.summary(),
            "deltas": [d.to_dict() for d in self.changed],
        }


#: A detection that gets this much slower is worth flagging even if it still fires.
_SLOWDOWN_FACTOR = 2.0
_SLOWDOWN_FLOOR_SECONDS = 30.0


def diff_runs(
    current: RunRecord,
    previous: RunRecord | None,
    *,
    include_unchanged: bool = False,
) -> RunDiff:
    """Compare two runs case by case."""
    diff = RunDiff(
        baseline_run_id=previous.run_id if previous else None,
        current_run_id=current.run_id,
    )
    if previous is None:
        # A first run has nothing to regress against. Reporting every case as
        # "new" would drown the signal, so only the failures are surfaced.
        for result in current.results:
            if result.outcome in (Outcome.VISIBLE, Outcome.BLIND):
                diff.deltas.append(_delta(result, None, DeltaKind.NEW))
        return diff

    before = {_key(r): r for r in previous.results}
    after = {_key(r): r for r in current.results}

    for key, result in after.items():
        prior = before.get(key)
        if prior is None:
            diff.deltas.append(_delta(result, None, DeltaKind.NEW))
            continue

        kind = _compare(prior, result)
        if kind is DeltaKind.UNCHANGED and not include_unchanged:
            continue
        diff.deltas.append(_delta(result, prior, kind))

    for key, prior in before.items():
        if key not in after:
            diff.deltas.append(
                CaseDelta(
                    key=key,
                    rule_name=prior.case.rule_name,
                    emulation_id=prior.case.emulation_id,
                    kind=DeltaKind.REMOVED,
                    before=prior.outcome,
                    after=None,
                    severity=prior.case.severity.value,
                    note="case is no longer in the plan - rule deleted, disabled, "
                    "or filtered out of the profile",
                )
            )

    diff.deltas.sort(key=lambda d: (_kind_order(d.kind), d.rule_name))
    return diff


def _compare(previous: CaseResult, current: CaseResult) -> DeltaKind:
    # Operational states are not comparable evidence in either direction.
    if not previous.outcome.is_scoreable or not current.outcome.is_scoreable:
        return DeltaKind.UNCHANGED

    before = outcome_rank(previous.outcome)
    after = outcome_rank(current.outcome)
    if after < before:
        return DeltaKind.REGRESSION
    if after > before:
        return DeltaKind.IMPROVEMENT

    if (
        current.outcome is Outcome.DETECTED
        and previous.latency_seconds
        and current.latency_seconds
        and current.latency_seconds > max(
            previous.latency_seconds * _SLOWDOWN_FACTOR, _SLOWDOWN_FLOOR_SECONDS
        )
    ):
        return DeltaKind.SLOWER

    return DeltaKind.UNCHANGED


def _delta(
    current: CaseResult,
    previous: CaseResult | None,
    kind: DeltaKind,
) -> CaseDelta:
    note = ""
    if kind is DeltaKind.REGRESSION and current.outcome is Outcome.BLIND:
        note = (
            "telemetry stopped arriving; check collection before touching the rule"
        )
    elif kind is DeltaKind.REGRESSION and current.outcome is Outcome.VISIBLE:
        note = "telemetry still arrives but the rule no longer matches it"
    elif kind is DeltaKind.NEW:
        note = "no prior result for this case"
    elif kind is DeltaKind.SLOWER:
        note = "still detected, but materially slower than the previous run"

    return CaseDelta(
        key=_key(current),
        rule_name=current.case.rule_name,
        emulation_id=current.case.emulation_id,
        kind=kind,
        before=previous.outcome if previous else None,
        after=current.outcome,
        before_latency=previous.latency_seconds if previous else None,
        after_latency=current.latency_seconds,
        severity=current.case.severity.value,
        note=note,
    )


def _key(result: CaseResult) -> str:
    return f"{result.case.rule_name}|{result.case.emulation_id}"


def _kind_order(kind: DeltaKind) -> int:
    return {
        DeltaKind.REGRESSION: 0,
        DeltaKind.SLOWER: 1,
        DeltaKind.NEW: 2,
        DeltaKind.REMOVED: 3,
        DeltaKind.IMPROVEMENT: 4,
        DeltaKind.UNCHANGED: 5,
    }[kind]


def rules_changed(current: Iterable[str], previous: Iterable[str]) -> dict[str, list[str]]:
    """Compare two sets of rule fingerprints to see which logic changed."""
    before = set(previous)
    after = set(current)
    return {
        "added": sorted(after - before),
        "removed": sorted(before - after),
    }
