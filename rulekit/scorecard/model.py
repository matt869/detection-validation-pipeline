"""Scorecard data model.

A scorecard answers a different question from the linter. The linter asks "is
anything wrong with this rule?"; the scorecard asks "how much should we trust
this rule?" - and produces a number that can be tracked over time, compared
between teams, and used as a release gate.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = ["DimensionScore", "Grade", "LibraryScore", "RuleScore"]

_GRADE_THRESHOLDS = ((90.0, "A"), (80.0, "B"), (70.0, "C"), (60.0, "D"), (0.0, "F"))


class Grade:
    """Letter grades from a 0-100 score."""

    @staticmethod
    def of(score: float) -> str:
        for threshold, letter in _GRADE_THRESHOLDS:
            if score >= threshold:
                return letter
        return "F"


@dataclass(frozen=True, slots=True)
class DimensionScore:
    """One weighted axis of rule quality."""

    name: str
    score: float  # 0..100
    weight: float
    #: Human-readable reasons for lost points, shown in the report.
    deductions: tuple[str, ...] = ()
    #: What this dimension measures, shown in ``dvp rules score --explain``.
    rationale: str = ""

    @property
    def weighted(self) -> float:
        return self.score * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 1),
            "weight": self.weight,
            "weighted": round(self.weighted, 2),
            "deductions": list(self.deductions),
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class RuleScore:
    """The full scorecard for one rule."""

    rule_name: str
    title: str
    dimensions: tuple[DimensionScore, ...]
    severity: str = "medium"
    status: str = "experimental"
    techniques: tuple[str, ...] = ()

    @property
    def total(self) -> float:
        total_weight = sum(d.weight for d in self.dimensions)
        if total_weight == 0:
            return 0.0
        return round(sum(d.weighted for d in self.dimensions) / total_weight, 1)

    @property
    def grade(self) -> str:
        return Grade.of(self.total)

    @property
    def weakest(self) -> DimensionScore | None:
        scored = [d for d in self.dimensions if d.weight > 0]
        return min(scored, key=lambda d: d.score) if scored else None

    def deductions(self) -> list[str]:
        return [text for dimension in self.dimensions for text in dimension.deductions]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "techniques": list(self.techniques),
            "total": self.total,
            "grade": self.grade,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }


@dataclass(slots=True)
class LibraryScore:
    """Rollup across every scored rule."""

    rules: list[RuleScore] = field(default_factory=list)

    @property
    def average(self) -> float:
        return round(sum(r.total for r in self.rules) / len(self.rules), 1) if self.rules else 0.0

    @property
    def grade(self) -> str:
        return Grade.of(self.average)

    def distribution(self) -> dict[str, int]:
        counts = {letter: 0 for _, letter in _GRADE_THRESHOLDS}
        for rule in self.rules:
            counts[rule.grade] += 1
        return counts

    def by_dimension(self) -> dict[str, float]:
        """Average score per dimension - shows where the library is systemically weak."""
        totals: dict[str, list[float]] = {}
        for rule in self.rules:
            for dimension in rule.dimensions:
                totals.setdefault(dimension.name, []).append(dimension.score)
        return {name: round(sum(v) / len(v), 1) for name, v in sorted(totals.items())}

    def worst(self, limit: int = 10) -> list[RuleScore]:
        return sorted(self.rules, key=lambda r: r.total)[:limit]

    def below(self, threshold: float) -> list[RuleScore]:
        return [r for r in self.rules if r.total < threshold]

    def to_dict(self) -> dict[str, Any]:
        return {
            "average": self.average,
            "grade": self.grade,
            "count": len(self.rules),
            "distribution": self.distribution(),
            "by_dimension": self.by_dimension(),
            "rules": [r.to_dict() for r in self.rules],
        }

    def extend(self, scores: Iterable[RuleScore]) -> None:
        self.rules.extend(scores)
