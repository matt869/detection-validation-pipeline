"""ATT&CK coverage measured from validation results, not from rule counts.

The distinction matters. Counting rules per technique measures effort; this
measures effect. A technique with four rules that all resolve to ``BLIND``
scores zero here, and it should - nothing is being detected.

Two numbers are reported per technique, because they have different owners:

``detection_rate``   fraction of cases that fired. Owned by detection engineering.
``visibility_rate``  fraction where the telemetry arrived at all. Owned by the
                     platform team. A low visibility rate makes the detection
                     rate meaningless, so it is reported first.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.core.models import Outcome, RunRecord
from harness.core.yamlio import load_yaml

__all__ = [
    "AttackReference",
    "CoverageReport",
    "CoverageTargets",
    "TacticCoverage",
    "TechniqueCoverage",
    "build_coverage",
]

_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@dataclass(slots=True)
class AttackReference:
    """Parsed ``mapping/mapping.yml``."""

    tactics: dict[str, dict[str, Any]] = field(default_factory=dict)
    techniques: dict[str, dict[str, Any]] = field(default_factory=dict)
    version: str = ""

    def technique_name(self, technique: str) -> str:
        entry = self.techniques.get(technique)
        if entry:
            return str(entry.get("name") or technique)
        parent = self.techniques.get(technique.split(".", 1)[0])
        return str(parent.get("name")) if parent else technique

    def tactics_for(self, technique: str) -> list[str]:
        entry = self.techniques.get(technique) or self.techniques.get(technique.split(".", 1)[0])
        return [str(t) for t in (entry or {}).get("tactics", [])]

    def telemetry_for(self, technique: str) -> list[str]:
        entry = self.techniques.get(technique) or self.techniques.get(technique.split(".", 1)[0])
        return [str(t) for t in (entry or {}).get("telemetry", [])]

    def tactic_name(self, tactic: str) -> str:
        return str((self.tactics.get(tactic) or {}).get("name") or tactic)

    def tactic_order(self, tactic: str) -> int:
        return int((self.tactics.get(tactic) or {}).get("order", 99))

    @classmethod
    def load(cls, path: Path | str) -> AttackReference:
        document = load_yaml(path, default={}) or {}
        return cls(
            tactics={str(k): dict(v or {}) for k, v in (document.get("tactics") or {}).items()},
            techniques={
                str(k): dict(v or {}) for k, v in (document.get("techniques") or {}).items()
            },
            version=str(document.get("attack_version") or ""),
        )

    @classmethod
    def empty(cls) -> AttackReference:
        return cls()


@dataclass(slots=True)
class CoverageTargets:
    """Parsed ``mapping/coverage_targets.yml``."""

    default_detected: float = 0.70
    default_visible: float = 0.90
    tactics: dict[str, dict[str, Any]] = field(default_factory=dict)
    techniques: dict[str, dict[str, Any]] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)

    def for_technique(self, technique: str, tactics: Iterable[str]) -> tuple[float, float, str]:
        """Resolve (detected target, visible target, priority) for a technique.

        Technique-level entries win; otherwise the strictest matching tactic
        target applies, because a technique that serves two tactics should be
        held to the higher bar of the two.
        """
        entry = self.techniques.get(technique) or self.techniques.get(technique.split(".", 1)[0])
        if entry:
            return (
                float(entry.get("detected", self.default_detected)),
                float(entry.get("visible", self.default_visible)),
                str(entry.get("priority", "medium")),
            )

        detected = self.default_detected
        visible = self.default_visible
        priority = "medium"
        for tactic in tactics:
            target = self.tactics.get(tactic)
            if not target:
                continue
            detected = max(detected, float(target.get("detected", self.default_detected)))
            visible = max(visible, float(target.get("visible", self.default_visible)))
            candidate = str(target.get("priority", "medium"))
            if _PRIORITY_ORDER.get(candidate, 9) < _PRIORITY_ORDER.get(priority, 9):
                priority = candidate
        return detected, visible, priority

    def is_excluded(self, technique: str) -> bool:
        return technique in self.excluded or technique.split(".", 1)[0] in self.excluded

    @classmethod
    def load(cls, path: Path | str) -> CoverageTargets:
        document = load_yaml(path, default={}) or {}
        defaults = document.get("defaults") or {}
        excluded = {}
        for entry in document.get("excluded") or []:
            if isinstance(entry, Mapping) and entry.get("technique"):
                excluded[str(entry["technique"])] = str(entry.get("reason") or "")
        return cls(
            default_detected=float(defaults.get("detected", 0.70)),
            default_visible=float(defaults.get("visible", 0.90)),
            tactics={str(k): dict(v or {}) for k, v in (document.get("tactics") or {}).items()},
            techniques={
                str(k): dict(v or {}) for k, v in (document.get("techniques") or {}).items()
            },
            excluded=excluded,
        )

    @classmethod
    def empty(cls) -> CoverageTargets:
        return cls()


@dataclass(slots=True)
class TechniqueCoverage:
    technique: str
    name: str = ""
    tactics: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    detected: int = 0
    visible: int = 0
    blind: int = 0
    errored: int = 0
    skipped: int = 0
    target_detected: float = 0.0
    target_visible: float = 0.0
    priority: str = "medium"
    missing_telemetry: tuple[str, ...] = ()

    @property
    def scoreable(self) -> int:
        return self.detected + self.visible + self.blind

    @property
    def detection_rate(self) -> float:
        return self.detected / self.scoreable if self.scoreable else 0.0

    @property
    def visibility_rate(self) -> float:
        return (self.detected + self.visible) / self.scoreable if self.scoreable else 0.0

    @property
    def meets_detection_target(self) -> bool:
        return self.scoreable > 0 and self.detection_rate >= self.target_detected

    @property
    def meets_visibility_target(self) -> bool:
        return self.scoreable > 0 and self.visibility_rate >= self.target_visible

    @property
    def status(self) -> str:
        """``covered`` / ``partial`` / ``detection-gap`` / ``visibility-gap`` / ``untested``."""
        if self.scoreable == 0:
            return "untested"
        if self.blind == self.scoreable:
            return "visibility-gap"
        if self.detected == 0:
            return "detection-gap"
        if self.meets_detection_target and self.meets_visibility_target:
            return "covered"
        return "partial"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "name": self.name,
            "tactics": list(self.tactics),
            "rules": list(self.rules),
            "detected": self.detected,
            "visible": self.visible,
            "blind": self.blind,
            "errored": self.errored,
            "skipped": self.skipped,
            "detection_rate": round(self.detection_rate, 4),
            "visibility_rate": round(self.visibility_rate, 4),
            "target_detected": self.target_detected,
            "target_visible": self.target_visible,
            "meets_detection_target": self.meets_detection_target,
            "meets_visibility_target": self.meets_visibility_target,
            "priority": self.priority,
            "status": self.status,
            "missing_telemetry": list(self.missing_telemetry),
        }


@dataclass(slots=True)
class TacticCoverage:
    tactic: str
    name: str = ""
    order: int = 99
    techniques: list[TechniqueCoverage] = field(default_factory=list)
    target_detected: float = 0.0
    target_visible: float = 0.0
    priority: str = "medium"

    @property
    def detected(self) -> int:
        return sum(t.detected for t in self.techniques)

    @property
    def scoreable(self) -> int:
        return sum(t.scoreable for t in self.techniques)

    @property
    def blind(self) -> int:
        return sum(t.blind for t in self.techniques)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.scoreable if self.scoreable else 0.0

    @property
    def visibility_rate(self) -> float:
        return (self.scoreable - self.blind) / self.scoreable if self.scoreable else 0.0

    @property
    def meets_target(self) -> bool:
        return (
            self.scoreable > 0
            and self.detection_rate >= self.target_detected
            and self.visibility_rate >= self.target_visible
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic": self.tactic,
            "name": self.name,
            "order": self.order,
            "priority": self.priority,
            "techniques": [t.technique for t in self.techniques],
            "detected": self.detected,
            "scoreable": self.scoreable,
            "detection_rate": round(self.detection_rate, 4),
            "visibility_rate": round(self.visibility_rate, 4),
            "target_detected": self.target_detected,
            "target_visible": self.target_visible,
            "meets_target": self.meets_target,
        }


@dataclass(slots=True)
class CoverageReport:
    techniques: dict[str, TechniqueCoverage] = field(default_factory=dict)
    tactics: dict[str, TacticCoverage] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)
    attack_version: str = ""

    @property
    def detection_rate(self) -> float:
        scoreable = sum(t.scoreable for t in self.techniques.values())
        detected = sum(t.detected for t in self.techniques.values())
        return detected / scoreable if scoreable else 0.0

    @property
    def visibility_rate(self) -> float:
        scoreable = sum(t.scoreable for t in self.techniques.values())
        blind = sum(t.blind for t in self.techniques.values())
        return (scoreable - blind) / scoreable if scoreable else 0.0

    def failing_tactics(self) -> list[TacticCoverage]:
        return sorted(
            (t for t in self.tactics.values() if t.scoreable and not t.meets_target),
            key=lambda t: (_PRIORITY_ORDER.get(t.priority, 9), t.order),
        )

    def gaps(self, kind: str) -> list[TechniqueCoverage]:
        """Techniques with at least one case in that gap state.

        ``kind`` is ``detection`` or ``visibility``.

        Deliberately keyed on the case counts rather than on ``status``, which
        collapses a technique to one word and only says ``visibility-gap`` when
        *every* case is blind. One technique can be covered by two rules
        reading two sensors: T1562.001 is detected through the Sysmon registry
        write and blind on the Defender channel that is not forwarded. Selecting
        on ``status`` would drop it from this list the moment the compensating
        rule was added - deleting an uncollected log source from the report
        because something else happened to catch the behaviour, which is the
        green tick over a hole this tool exists to prevent. A gap covered from
        another angle is still a gap.
        """
        if kind == "detection":
            selected = (t for t in self.techniques.values() if t.visible)
        else:
            selected = (t for t in self.techniques.values() if t.blind)
        return sorted(
            selected,
            key=lambda t: (_PRIORITY_ORDER.get(t.priority, 9), t.technique),
        )

    def by_priority(self) -> list[TechniqueCoverage]:
        return sorted(
            self.techniques.values(),
            key=lambda t: (_PRIORITY_ORDER.get(t.priority, 9), -t.blind, t.technique),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_version": self.attack_version,
            "detection_rate": round(self.detection_rate, 4),
            "visibility_rate": round(self.visibility_rate, 4),
            "techniques": {k: v.to_dict() for k, v in sorted(self.techniques.items())},
            "tactics": {
                k: v.to_dict() for k, v in sorted(self.tactics.items(), key=lambda kv: kv[1].order)
            },
            "excluded": dict(self.excluded),
        }


def build_coverage(
    run: RunRecord,
    *,
    reference: AttackReference | None = None,
    targets: CoverageTargets | None = None,
) -> CoverageReport:
    """Aggregate a run's case results into per-technique and per-tactic coverage."""
    reference = reference or AttackReference.empty()
    targets = targets or CoverageTargets.empty()

    buckets: dict[str, TechniqueCoverage] = {}
    rules_by_technique: dict[str, set[str]] = defaultdict(set)
    blind_telemetry: dict[str, set[str]] = defaultdict(set)

    for result in run.results:
        for ref in result.case.attack:
            technique = ref.technique
            if not technique or targets.is_excluded(technique):
                continue

            # Named `technique_tactics` because `tactics` below is the report's
            # per-tactic index; two different shapes under one name is how a
            # later edit reaches for the wrong one.
            technique_tactics = [ref.tactic] if ref.tactic else reference.tactics_for(technique)
            technique_tactics = [t for t in technique_tactics if t]
            bucket = buckets.get(technique)
            if bucket is None:
                detected_target, visible_target, priority = targets.for_technique(
                    technique, technique_tactics
                )
                bucket = TechniqueCoverage(
                    technique=technique,
                    name=reference.technique_name(technique),
                    tactics=tuple(dict.fromkeys(technique_tactics)),
                    target_detected=detected_target,
                    target_visible=visible_target,
                    priority=priority,
                )
                buckets[technique] = bucket

            rules_by_technique[technique].add(result.case.rule_name)

            if result.outcome is Outcome.DETECTED:
                bucket.detected += 1
            elif result.outcome is Outcome.VISIBLE:
                bucket.visible += 1
            elif result.outcome is Outcome.BLIND:
                bucket.blind += 1
                # Naming the source turns "we are blind here" into a work item.
                blind_telemetry[technique].update(result.case.telemetry)
            elif result.outcome is Outcome.ERROR:
                bucket.errored += 1
            else:
                bucket.skipped += 1

    for technique, bucket in buckets.items():
        bucket.rules = tuple(sorted(rules_by_technique[technique]))
        bucket.missing_telemetry = tuple(sorted(blind_telemetry.get(technique, ())))

    tactics: dict[str, TacticCoverage] = {}
    for bucket in buckets.values():
        for tactic in bucket.tactics or ("unmapped",):
            entry = tactics.get(tactic)
            if entry is None:
                target = targets.tactics.get(tactic) or {}
                entry = TacticCoverage(
                    tactic=tactic,
                    name=reference.tactic_name(tactic),
                    order=reference.tactic_order(tactic),
                    target_detected=float(target.get("detected", targets.default_detected)),
                    target_visible=float(target.get("visible", targets.default_visible)),
                    priority=str(target.get("priority", "medium")),
                )
                tactics[tactic] = entry
            entry.techniques.append(bucket)

    return CoverageReport(
        techniques=buckets,
        tactics=tactics,
        excluded=dict(targets.excluded),
        attack_version=reference.version,
    )
