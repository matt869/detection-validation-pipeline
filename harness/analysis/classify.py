"""The three-state classifier.

This is the module the whole pipeline exists to serve. Given what the backend
returned for one validation case, it decides which of ``DETECTED`` /
``VISIBLE`` / ``BLIND`` describes reality, and separately whether that matches
what the rule author expected.

The decision order matters, and each step encodes a judgement:

1. **Did the behaviour actually happen?** If emulation was skipped or errored,
   the case is ``SKIPPED``. Reporting ``BLIND`` for a test that never ran would
   manufacture a visibility gap out of an operational failure.
2. **Did the query itself fail?** ``ERROR``. A backend timeout is not evidence
   of anything about the detection.
3. **Did the rule fire?** ``DETECTED``.
4. **Can we even tell the difference?** Without a telemetry probe the honest
   answer is "we do not know". The classifier reports ``VISIBLE`` with low
   confidence and says so in a note, rather than blaming the log pipeline for
   something that might be a rule bug.
5. **Did the telemetry arrive?** ``VISIBLE`` if yes, ``BLIND`` if no.

Outcome and expectation are kept on separate axes. A rule that documents
``expect: visible`` because a log source is not onboarded produces outcome
``VISIBLE`` and status ``PASS``: a known gap, already owned and dated, must not
page anyone. If it starts firing anyway, status becomes ``UNEXPECTED_PASS``,
which is the signal to update the rule rather than to celebrate quietly.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from harness.backends.base import QueryResult
from harness.core.models import (
    CaseResult,
    CaseStatus,
    Confidence,
    EmulationResult,
    Outcome,
    ValidationCase,
)
from harness.core.timeutil import to_utc

__all__ = ["Observation", "classify", "outcome_rank", "redact"]

#: BLIND < VISIBLE < DETECTED. Used to decide whether an outcome is better or
#: worse than the documented expectation.
_OUTCOME_RANK = {Outcome.BLIND: 0, Outcome.VISIBLE: 1, Outcome.DETECTED: 2}


def outcome_rank(outcome: Outcome) -> int:
    return _OUTCOME_RANK.get(outcome, -1)


@dataclass(slots=True)
class Observation:
    """Everything collected for one case, before interpretation."""

    #: Result of running the rule's own detection logic.
    detection: QueryResult | None = None
    #: Result of the log-source presence probe. ``None`` means no probe exists.
    telemetry: QueryResult | None = None
    #: Result of running the detection logic over the quiet baseline window.
    baseline: QueryResult | None = None
    emulation: EmulationResult | None = None
    #: Reason the case never ran, if it did not.
    skip_reason: str | None = None
    queries: dict[str, str] = field(default_factory=dict)

    @property
    def probe_available(self) -> bool:
        return self.telemetry is not None


def classify(
    case: ValidationCase,
    observation: Observation,
    *,
    evidence_limit: int = 3,
    redact_fields: Sequence[str] = (),
    store_evidence: bool = True,
) -> CaseResult:
    """Turn raw query results into a verdict."""
    notes: list[str] = []
    confidence = Confidence.HIGH

    # -- 1. did the behaviour happen at all? -------------------------------
    skip = observation.skip_reason or case.skip_reason
    if skip:
        return _skipped(case, observation, skip)

    emulation = observation.emulation
    if emulation is None:
        return _skipped(case, observation, "emulation produced no result")
    if emulation.mode == "dry-run":
        return _skipped(
            case,
            observation,
            "dry run: no behaviour was emulated, so no conclusion can be drawn",
        )
    if emulation.error:
        return _errored(case, observation, f"emulation failed: {emulation.error}")

    # -- 2. did the queries succeed? ---------------------------------------
    detection = observation.detection
    if detection is None:
        return _errored(case, observation, "detection query was never run")
    if not detection.ok:
        return _errored(case, observation, f"detection query failed: {detection.error}")

    telemetry = observation.telemetry
    if telemetry is not None and not telemetry.ok:
        notes.append(f"telemetry probe failed ({telemetry.error}); treating as unavailable")
        telemetry = None
        confidence = Confidence.LOW

    detection_hits = detection.count
    telemetry_hits = telemetry.count if telemetry is not None else 0

    # -- 3-5. the three states ---------------------------------------------
    if detection_hits > 0:
        outcome = Outcome.DETECTED
    elif telemetry is None:
        outcome = Outcome.VISIBLE
        confidence = Confidence.LOW
        notes.append(
            "no telemetry probe is defined for this rule, so a detection gap "
            "cannot be distinguished from a visibility gap; reported as VISIBLE "
            "because blaming the log pipeline without evidence is the worse error"
        )
    elif telemetry_hits > 0:
        outcome = Outcome.VISIBLE
        notes.append(
            f"{telemetry_hits} telemetry event(s) arrived but the rule matched none "
            "of them - this is a detection gap, not a logging gap"
        )
    else:
        outcome = Outcome.BLIND
        notes.append(
            "no telemetry of the required type arrived during the test window - "
            "fix collection before tuning the rule"
        )

    # -- confidence adjustments --------------------------------------------
    if detection.truncated or (telemetry is not None and telemetry.truncated):
        confidence = _lower(confidence, Confidence.MEDIUM)
        notes.append("result set was truncated; latency is a lower bound")
    if not emulation.executed and emulation.mode == "replay":
        confidence = _lower(confidence, Confidence.MEDIUM)
        notes.append("replayed from a recorded corpus, not executed live")
    if emulation.exit_code not in (None, 0):
        notes.append(
            f"emulation exited {emulation.exit_code}; the behaviour may have been "
            "blocked, which is itself worth knowing"
        )

    # -- latency -----------------------------------------------------------
    latency, first_at = _latency(detection, emulation)
    if latency is not None and latency > case.max_latency_seconds:
        notes.append(
            f"detected after {latency:.0f}s against a {case.max_latency_seconds:.0f}s budget"
        )

    # -- noise -------------------------------------------------------------
    baseline_hits = 0
    if observation.baseline is not None:
        if observation.baseline.ok:
            baseline_hits = observation.baseline.count
            if baseline_hits:
                notes.append(
                    f"the same logic matched {baseline_hits} event(s) in the quiet "
                    "baseline window - this rule generates noise regardless of its outcome"
                )
        else:
            notes.append(f"baseline query failed: {observation.baseline.error}")

    status = _status(outcome, case.expected)
    evidence = (
        redact(detection.sample(evidence_limit, case_fields(case)), redact_fields)
        if store_evidence
        else []
    )

    return CaseResult(
        case=case,
        outcome=outcome,
        status=status,
        confidence=confidence,
        detection_hits=detection_hits,
        telemetry_hits=telemetry_hits,
        baseline_hits=baseline_hits,
        latency_seconds=latency,
        first_detection_at=first_at,
        emulation=emulation,
        evidence=evidence,
        notes=notes,
        queries=dict(observation.queries),
    )


def case_fields(case: ValidationCase) -> Sequence[str]:
    """Fields to project into evidence. Empty means "let the event decide"."""
    return ()


def _status(outcome: Outcome, expected: Outcome) -> CaseStatus:
    actual_rank = outcome_rank(outcome)
    expected_rank = outcome_rank(expected)
    if actual_rank < 0 or expected_rank < 0:
        return CaseStatus.ERROR
    if actual_rank > expected_rank:
        # Better than documented. Not a failure, but the rule's metadata is now
        # wrong, and stale metadata is how known gaps become forgotten gaps.
        return CaseStatus.UNEXPECTED_PASS
    if actual_rank == expected_rank:
        return CaseStatus.PASS
    return CaseStatus.FAIL


def _latency(detection: QueryResult, emulation: EmulationResult):
    """Seconds from the start of the behaviour to the first matching event."""
    first = detection.earliest()
    if first is None or emulation.started_at is None:
        return None, None
    delta = (to_utc(first) - to_utc(emulation.started_at)).total_seconds()
    # A negative delta means the match predates the behaviour: the rule matched
    # something else in the padded window, so the number is not a latency.
    if delta < 0:
        return None, first
    return round(delta, 3), first


def _lower(current: Confidence, floor: Confidence) -> Confidence:
    order = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
    return current if order[current] <= order[floor] else floor


def _skipped(case: ValidationCase, observation: Observation, reason: str) -> CaseResult:
    return CaseResult(
        case=case,
        outcome=Outcome.SKIPPED,
        status=CaseStatus.SKIPPED,
        confidence=Confidence.HIGH,
        emulation=observation.emulation,
        notes=[reason],
        queries=dict(observation.queries),
    )


def _errored(case: ValidationCase, observation: Observation, reason: str) -> CaseResult:
    return CaseResult(
        case=case,
        outcome=Outcome.ERROR,
        status=CaseStatus.ERROR,
        confidence=Confidence.LOW,
        emulation=observation.emulation,
        error=reason,
        notes=[reason],
        queries=dict(observation.queries),
    )


def redact(
    samples: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> list[dict[str, Any]]:
    """Replace the value of any field whose name contains a redaction term.

    Evidence is stored in a database and rendered into reports that get shared
    outside the security team, so a command line containing a password must not
    survive the trip. Matching is on substring and case-insensitive, because the
    field is as likely to be called ``svc_password`` as ``password``.
    """
    if not fields:
        return [dict(sample) for sample in samples]

    terms = [f.casefold() for f in fields if f]
    cleaned: list[dict[str, Any]] = []
    for sample in samples:
        row: dict[str, Any] = {}
        for key, value in sample.items():
            if any(term in str(key).casefold() for term in terms):
                row[key] = "[redacted]"
            else:
                row[key] = value
        cleaned.append(row)
    return cleaned
