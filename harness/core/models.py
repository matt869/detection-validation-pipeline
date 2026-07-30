"""Core domain model.

These dataclasses are the contract between every stage of the pipeline:
planner -> emulator -> collector -> classifier -> scorer -> reporter -> storage.

They are plain dataclasses (no pydantic) so the core has exactly one runtime
dependency, and every one of them round-trips through ``to_dict``/``from_dict``
so a run can be serialised to JSON, stored in SQLite, and replayed offline.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from harness.core.timeutil import TimeWindow, parse_ts, to_iso, utcnow


class Severity(str, Enum):
    """Rule severity, ordered so gates can say "fail on high and above"."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    @classmethod
    def parse(cls, value: object, *, default: Severity = None) -> Severity:  # type: ignore[assignment]
        if isinstance(value, Severity):
            return value
        text = str(value or "").strip().lower()
        aliases = {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "crit": cls.CRITICAL,
        }
        if text in aliases:
            return aliases[text]
        try:
            return cls(text)
        except ValueError:
            if default is not None:
                return default
            raise


_SEVERITY_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class RuleStatus(str, Enum):
    """Lifecycle stage of a detection rule."""

    EXPERIMENTAL = "experimental"
    TEST = "test"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class Outcome(str, Enum):
    """The three-state validation outcome, plus two operational states.

    The three states are mutually exclusive and jointly exhaustive for any case
    that actually executed:

    ``DETECTED``  the rule fired - the control works end to end.
    ``VISIBLE``   the telemetry arrived but the rule did not fire.
                  This is a *detection gap*: fix the rule.
    ``BLIND``     the telemetry never arrived. This is a *visibility gap*:
                  fix logging, forwarding, or licensing. Tuning the rule is
                  pointless until this is resolved.

    ``ERROR`` and ``SKIPPED`` are operational states. They are excluded from
    coverage arithmetic because counting them would silently inflate or deflate
    scores when infrastructure misbehaves.
    """

    DETECTED = "detected"
    VISIBLE = "visible"
    BLIND = "blind"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def is_scoreable(self) -> bool:
        """Whether this outcome participates in coverage arithmetic."""
        return self in _SCOREABLE

    @property
    def gap_kind(self) -> str | None:
        """Which remediation queue this outcome belongs in."""
        if self is Outcome.VISIBLE:
            return "detection"
        if self is Outcome.BLIND:
            return "visibility"
        return None

    @property
    def symbol(self) -> str:
        return _OUTCOME_SYMBOL[self]


_SCOREABLE = frozenset({Outcome.DETECTED, Outcome.VISIBLE, Outcome.BLIND})
_OUTCOME_SYMBOL = {
    Outcome.DETECTED: "+",
    Outcome.VISIBLE: "!",
    Outcome.BLIND: "x",
    Outcome.ERROR: "E",
    Outcome.SKIPPED: "-",
}


class CaseStatus(str, Enum):
    """Whether the observed outcome matched what the rule author expected.

    Outcome and status are separate axes on purpose. A rule that documents
    ``expect: visible`` because the log source is not yet onboarded produces
    outcome ``VISIBLE`` and status ``PASS`` - it is a known, accepted gap, and
    it must not page anyone. If it later starts firing, status becomes
    ``UNEXPECTED_PASS``, which is the signal to update the rule's expectation.
    """

    PASS = "pass"
    FAIL = "fail"
    UNEXPECTED_PASS = "unexpected_pass"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def is_failure(self) -> bool:
        return self in (CaseStatus.FAIL, CaseStatus.ERROR)


class Confidence(str, Enum):
    """How much weight to place on a case result.

    Degraded confidence never changes the outcome, it annotates it - an
    operator reading a report needs to know that a ``BLIND`` result came from a
    backend that timed out on the telemetry probe.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class AttackRef:
    """An ATT&CK technique reference with its tactic context."""

    technique: str
    tactic: str | None = None
    subtechnique_of: str | None = None
    name: str | None = None

    @property
    def base_technique(self) -> str:
        """``T1003.001`` -> ``T1003``."""
        return self.technique.split(".", 1)[0]

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "tactic": self.tactic,
            "subtechnique_of": self.subtechnique_of,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AttackRef:
        return cls(
            technique=str(data["technique"]),
            tactic=data.get("tactic"),
            subtechnique_of=data.get("subtechnique_of"),
            name=data.get("name"),
        )


@dataclass(slots=True)
class Event:
    """A single normalised telemetry record returned by a backend.

    ``raw`` keeps the backend's original document so evidence in reports is
    faithful; ``get`` handles the impedance mismatch between flat Sigma field
    names and nested backend documents.
    """

    raw: dict[str, Any]
    timestamp: datetime | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = self._infer_timestamp()

    _TIME_FIELDS = ("_time", "@timestamp", "timestamp", "TimeGenerated", "UtcTime", "event_time")

    def _infer_timestamp(self) -> datetime | None:
        for key in self._TIME_FIELDS:
            found = self.get(key)
            if found is not None:
                parsed = parse_ts(found)
                if parsed is not None:
                    return parsed
        return None

    def get(self, field_name: str, default: Any = None) -> Any:
        """Resolve a field name against the raw document.

        Resolution order, first hit wins:

        1. exact key
        2. case-insensitive key
        3. dotted path (``process.command_line``)
        4. unique leaf name anywhere in the nested document

        Step 4 is what lets one Sigma rule work against both a flat Windows
        event log export and an ECS-shaped Elastic document. It only matches
        when the leaf name is *unambiguous*, so it cannot silently pick the
        wrong field.
        """
        if field_name in self.raw:
            return self.raw[field_name]

        lowered = field_name.lower()
        for key, value in self.raw.items():
            if key.lower() == lowered:
                return value

        if "." in field_name:
            found = _walk_path(self.raw, field_name.split("."))
            if found is not _MISSING:
                return found

        matches = _find_leaves(self.raw, lowered)
        if len(matches) == 1:
            return matches[0]
        return default

    def has(self, field_name: str) -> bool:
        return self.get(field_name, _MISSING) is not _MISSING

    def to_dict(self) -> dict[str, Any]:
        return {"timestamp": to_iso(self.timestamp), "source": self.source, "raw": self.raw}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Event:
        # Accept both the wrapped form and a bare backend document.
        if "raw" in data and isinstance(data["raw"], Mapping):
            return cls(
                raw=dict(data["raw"]),
                timestamp=parse_ts(data.get("timestamp")),
                source=data.get("source"),
            )
        return cls(raw=dict(data), source=data.get("source"))

    def summary(self, fields: Sequence[str] | None = None, *, limit: int = 6) -> dict[str, Any]:
        """A compact projection used as report evidence."""
        if fields:
            projected = {f: self.get(f) for f in fields if self.get(f) is not None}
            if projected:
                return projected
        flat = {k: v for k, v in self.raw.items() if not isinstance(v, (dict, list))}
        return dict(list(flat.items())[:limit])


_MISSING = object()


def _walk_path(document: Any, parts: Sequence[str]) -> Any:
    current = document
    for part in parts:
        if isinstance(current, Mapping):
            matched = _MISSING
            for key, value in current.items():
                if str(key).lower() == part.lower():
                    matched = value
                    break
            if matched is _MISSING:
                return _MISSING
            current = matched
        else:
            return _MISSING
    return current


def _find_leaves(document: Any, target: str, *, depth: int = 0) -> list[Any]:
    """Collect values whose key matches ``target`` anywhere in the document."""
    if depth > 6 or not isinstance(document, Mapping):
        return []
    found: list[Any] = []
    for key, value in document.items():
        if str(key).lower() == target:
            found.append(value)
        elif isinstance(value, Mapping):
            found.extend(_find_leaves(value, target, depth=depth + 1))
        elif isinstance(value, list):
            for item in value:
                found.extend(_find_leaves(item, target, depth=depth + 1))
    return found


@dataclass(slots=True)
class ValidationCase:
    """One planned unit of work: prove that *this rule* catches *this test*.

    Produced by the planner before anything executes, so a run can be reviewed
    (``--plan-only``) before any emulation touches an endpoint.
    """

    case_id: str
    rule_name: str
    rule_id: str
    rule_title: str
    severity: Severity
    attack: list[AttackRef]
    platform: str
    emulation_id: str
    backend: str
    expected: Outcome = Outcome.DETECTED
    telemetry: list[str] = field(default_factory=list)
    max_latency_seconds: float = 300.0
    tags: list[str] = field(default_factory=list)
    skip_reason: str | None = None

    @property
    def technique_ids(self) -> list[str]:
        return [ref.technique for ref in self.attack]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "attack": [ref.to_dict() for ref in self.attack],
            "platform": self.platform,
            "emulation_id": self.emulation_id,
            "backend": self.backend,
            "expected": self.expected.value,
            "telemetry": list(self.telemetry),
            "max_latency_seconds": self.max_latency_seconds,
            "tags": list(self.tags),
            "skip_reason": self.skip_reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationCase:
        return cls(
            case_id=data["case_id"],
            rule_name=data["rule_name"],
            rule_id=data.get("rule_id", ""),
            rule_title=data.get("rule_title", data["rule_name"]),
            severity=Severity.parse(data.get("severity"), default=Severity.MEDIUM),
            attack=[AttackRef.from_dict(a) for a in data.get("attack", [])],
            platform=data.get("platform", "unknown"),
            emulation_id=data["emulation_id"],
            backend=data.get("backend", "fixture"),
            expected=Outcome(data.get("expected", "detected")),
            telemetry=list(data.get("telemetry", [])),
            max_latency_seconds=float(data.get("max_latency_seconds", 300.0)),
            tags=list(data.get("tags", [])),
            skip_reason=data.get("skip_reason"),
        )


@dataclass(slots=True)
class EmulationResult:
    """What the emulation layer actually did (or declined to do)."""

    emulation_id: str
    executed: bool
    mode: str  # dry-run | replay | local | remote
    started_at: datetime | None = None
    finished_at: datetime | None = None
    host: str = "unknown"
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifacts: list[str] = field(default_factory=list)
    cleanup_performed: bool = False
    error: str | None = None

    @property
    def window(self) -> TimeWindow | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return TimeWindow(self.started_at, self.finished_at)

    @property
    def duration_seconds(self) -> float | None:
        w = self.window
        return w.duration_seconds if w else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "emulation_id": self.emulation_id,
            "executed": self.executed,
            "mode": self.mode,
            "started_at": to_iso(self.started_at),
            "finished_at": to_iso(self.finished_at),
            "host": self.host,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": list(self.artifacts),
            "cleanup_performed": self.cleanup_performed,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EmulationResult:
        return cls(
            emulation_id=data["emulation_id"],
            executed=bool(data.get("executed", False)),
            mode=data.get("mode", "dry-run"),
            started_at=parse_ts(data.get("started_at")),
            finished_at=parse_ts(data.get("finished_at")),
            host=data.get("host", "unknown"),
            exit_code=data.get("exit_code"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            artifacts=list(data.get("artifacts", [])),
            cleanup_performed=bool(data.get("cleanup_performed", False)),
            error=data.get("error"),
        )


@dataclass(slots=True)
class CaseResult:
    """The evidence and verdict for one validation case."""

    case: ValidationCase
    outcome: Outcome
    status: CaseStatus
    confidence: Confidence = Confidence.HIGH
    detection_hits: int = 0
    telemetry_hits: int = 0
    baseline_hits: int = 0
    latency_seconds: float | None = None
    first_detection_at: datetime | None = None
    emulation: EmulationResult | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    queries: dict[str, str] = field(default_factory=dict)

    @property
    def is_noisy(self) -> bool:
        """The rule matched activity in the quiet baseline window.

        A detection that also fires on baseline noise is not a working
        detection, it is an alert generator. Reported separately from outcome.
        """
        return self.baseline_hits > 0

    @property
    def breached_latency(self) -> bool:
        return (
            self.latency_seconds is not None
            and self.latency_seconds > self.case.max_latency_seconds
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "outcome": self.outcome.value,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "detection_hits": self.detection_hits,
            "telemetry_hits": self.telemetry_hits,
            "baseline_hits": self.baseline_hits,
            "latency_seconds": self.latency_seconds,
            "first_detection_at": to_iso(self.first_detection_at),
            "emulation": self.emulation.to_dict() if self.emulation else None,
            "evidence": self.evidence,
            "notes": list(self.notes),
            "error": self.error,
            "queries": dict(self.queries),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CaseResult:
        emulation = data.get("emulation")
        return cls(
            case=ValidationCase.from_dict(data["case"]),
            outcome=Outcome(data["outcome"]),
            status=CaseStatus(data["status"]),
            confidence=Confidence(data.get("confidence", "high")),
            detection_hits=int(data.get("detection_hits", 0)),
            telemetry_hits=int(data.get("telemetry_hits", 0)),
            baseline_hits=int(data.get("baseline_hits", 0)),
            latency_seconds=data.get("latency_seconds"),
            first_detection_at=parse_ts(data.get("first_detection_at")),
            emulation=EmulationResult.from_dict(emulation) if emulation else None,
            evidence=list(data.get("evidence", [])),
            notes=list(data.get("notes", [])),
            error=data.get("error"),
            queries=dict(data.get("queries", {})),
        )


@dataclass(slots=True)
class RunSummary:
    """Aggregate counters for a run. Cheap to compute, safe to recompute."""

    total: int = 0
    by_outcome: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    detection_rate: float = 0.0
    visibility_rate: float = 0.0
    noisy_rules: int = 0
    latency_p50: float | None = None
    latency_p95: float | None = None
    techniques_covered: int = 0
    techniques_total: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_outcome": dict(self.by_outcome),
            "by_status": dict(self.by_status),
            "by_severity": dict(self.by_severity),
            "detection_rate": self.detection_rate,
            "visibility_rate": self.visibility_rate,
            "noisy_rules": self.noisy_rules,
            "latency_p50": self.latency_p50,
            "latency_p95": self.latency_p95,
            "techniques_covered": self.techniques_covered,
            "techniques_total": self.techniques_total,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RunSummary:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass(slots=True)
class RunRecord:
    """Everything about one validation run. The unit of storage and reporting."""

    run_id: str
    profile: str
    backend: str
    started_at: datetime
    finished_at: datetime | None = None
    mode: str = "dry-run"
    operator: str = "unknown"
    git_ref: str | None = None
    results: list[CaseResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __iter__(self) -> Iterator[CaseResult]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def scoreable(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome.is_scoreable]

    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if r.status.is_failure]

    def gaps(self, kind: str) -> list[CaseResult]:
        """``kind`` is ``detection`` or ``visibility``."""
        return [r for r in self.results if r.outcome.gap_kind == kind]

    def summarise(self) -> RunSummary:
        scoreable = self.scoreable()
        outcomes = Counter(r.outcome.value for r in self.results)
        statuses = Counter(r.status.value for r in self.results)
        severities = Counter(
            r.case.severity.value for r in self.results if r.outcome is not Outcome.DETECTED
        )
        latencies = [r.latency_seconds for r in self.results if r.latency_seconds is not None]

        detected = outcomes.get(Outcome.DETECTED.value, 0)
        blind = outcomes.get(Outcome.BLIND.value, 0)
        denominator = len(scoreable)

        techniques: set[str] = set()
        covered: set[str] = set()
        for result in self.results:
            for technique in result.case.technique_ids:
                techniques.add(technique)
                if result.outcome is Outcome.DETECTED:
                    covered.add(technique)

        return RunSummary(
            total=len(self.results),
            by_outcome=dict(outcomes),
            by_status=dict(statuses),
            by_severity=dict(severities),
            detection_rate=(detected / denominator) if denominator else 0.0,
            # Visibility = the telemetry was there, whether or not the rule fired.
            visibility_rate=((denominator - blind) / denominator) if denominator else 0.0,
            noisy_rules=sum(1 for r in self.results if r.is_noisy),
            latency_p50=_percentile(latencies, 50),
            latency_p95=_percentile(latencies, 95),
            techniques_covered=len(covered),
            techniques_total=len(techniques),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "profile": self.profile,
            "backend": self.backend,
            "mode": self.mode,
            "operator": self.operator,
            "git_ref": self.git_ref,
            "started_at": to_iso(self.started_at),
            "finished_at": to_iso(self.finished_at),
            "duration_seconds": self.duration_seconds,
            "summary": self.summarise().to_dict(),
            "results": [r.to_dict() for r in self.results],
            "errors": list(self.errors),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RunRecord:
        started = parse_ts(data.get("started_at")) or utcnow()
        return cls(
            run_id=data["run_id"],
            profile=data.get("profile", "unknown"),
            backend=data.get("backend", "fixture"),
            started_at=started,
            finished_at=parse_ts(data.get("finished_at")),
            mode=data.get("mode", "dry-run"),
            operator=data.get("operator", "unknown"),
            git_ref=data.get("git_ref"),
            results=[CaseResult.from_dict(r) for r in data.get("results", [])],
            errors=list(data.get("errors", [])),
            metadata=dict(data.get("metadata", {})),
        )


def _percentile(values: Iterable[float], pct: int) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return round(ordered[0], 3)
    # ``inclusive`` keeps p95 of a small sample anchored to real observations
    # instead of extrapolating past the slowest measurement.
    quantiles = statistics.quantiles(ordered, n=100, method="inclusive")
    return round(quantiles[min(pct, 100) - 1], 3)
