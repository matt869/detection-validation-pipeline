"""The three-state classifier.

The most important tests in the suite: this is where the tool's central claim -
that it can tell a detection gap from a visibility gap - is either true or not.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from harness.analysis.classify import Observation, classify, redact
from harness.backends.base import QueryResult
from harness.core.models import CaseStatus, Confidence, Event, Outcome
from tests.conftest import make_case, make_emulation


def result(count: int = 1, *, offset: float = 3.0, anchor=None, truncated: bool = False):
    """A QueryResult with ``count`` events, ``offset`` seconds after ``anchor``."""
    events = []
    if anchor is not None:
        events = [
            Event(raw={"n": i}, timestamp=anchor + timedelta(seconds=offset)) for i in range(count)
        ]
    else:
        events = [Event(raw={"n": i}) for i in range(count)]
    return QueryResult(events=events, total=count, truncated=truncated)


def empty() -> QueryResult:
    return QueryResult(events=[], total=0)


# ------------------------------------------------------------- three states


def test_detection_hits_produce_detected():
    emulation = make_emulation()
    observation = Observation(
        detection=result(2, anchor=emulation.started_at),
        telemetry=result(5),
        emulation=emulation,
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.DETECTED
    assert outcome.status is CaseStatus.PASS


def test_telemetry_without_detection_is_a_detection_gap():
    observation = Observation(detection=empty(), telemetry=result(7), emulation=make_emulation())
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.VISIBLE
    assert outcome.telemetry_hits == 7
    assert "detection gap, not a logging gap" in " ".join(outcome.notes)


def test_no_telemetry_at_all_is_a_visibility_gap():
    observation = Observation(detection=empty(), telemetry=empty(), emulation=make_emulation())
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.BLIND
    assert "fix collection before tuning the rule" in " ".join(outcome.notes)


def test_missing_probe_reports_visible_at_low_confidence():
    # Without a probe the two gaps are indistinguishable. Blaming the log
    # pipeline without evidence is the worse error, so it reports VISIBLE and
    # says so rather than guessing silently.
    observation = Observation(detection=empty(), telemetry=None, emulation=make_emulation())
    outcome = classify(make_case(telemetry=[]), observation)
    assert outcome.outcome is Outcome.VISIBLE
    assert outcome.confidence is Confidence.LOW
    assert "cannot be distinguished" in " ".join(outcome.notes)


def test_failed_probe_degrades_to_low_confidence():
    observation = Observation(
        detection=empty(),
        telemetry=QueryResult.failed("timeout"),
        emulation=make_emulation(),
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.VISIBLE
    assert outcome.confidence is Confidence.LOW


# -------------------------------------------------- operational, not scored


def test_dry_run_is_skipped_not_blind():
    # Nothing was emulated, so reporting a visibility gap would manufacture one
    # out of an operational choice.
    observation = Observation(
        detection=empty(), telemetry=empty(), emulation=make_emulation(mode="dry-run")
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.SKIPPED
    assert outcome.status is CaseStatus.SKIPPED


def test_emulation_error_is_error_not_blind():
    observation = Observation(
        detection=empty(),
        telemetry=empty(),
        emulation=make_emulation(error="interpreter not found"),
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.ERROR
    assert outcome.status is CaseStatus.ERROR


def test_failed_detection_query_is_error_not_blind():
    observation = Observation(
        detection=QueryResult.failed("HTTP 503"),
        telemetry=result(3),
        emulation=make_emulation(),
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.ERROR
    assert "HTTP 503" in (outcome.error or "")


def test_safety_refusal_is_skipped_with_its_reason():
    observation = Observation(skip_reason="host not on the allowlist")
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.SKIPPED
    assert "allowlist" in " ".join(outcome.notes)


def test_operational_states_are_excluded_from_scoring():
    assert not Outcome.ERROR.is_scoreable
    assert not Outcome.SKIPPED.is_scoreable
    assert all(o.is_scoreable for o in (Outcome.DETECTED, Outcome.VISIBLE, Outcome.BLIND))


# ------------------------------------------------------- expectation axis


@pytest.mark.parametrize(
    ("observed_hits", "telemetry_hits", "expected", "status"),
    [
        (1, 5, Outcome.DETECTED, CaseStatus.PASS),
        (0, 5, Outcome.DETECTED, CaseStatus.FAIL),
        (0, 0, Outcome.DETECTED, CaseStatus.FAIL),
        (0, 5, Outcome.VISIBLE, CaseStatus.PASS),
        (0, 0, Outcome.VISIBLE, CaseStatus.FAIL),
        (0, 0, Outcome.BLIND, CaseStatus.PASS),
        (0, 5, Outcome.BLIND, CaseStatus.UNEXPECTED_PASS),
        (1, 5, Outcome.VISIBLE, CaseStatus.UNEXPECTED_PASS),
    ],
)
def test_status_compares_observed_against_expected(observed_hits, telemetry_hits, expected, status):
    observation = Observation(
        detection=result(observed_hits) if observed_hits else empty(),
        telemetry=result(telemetry_hits) if telemetry_hits else empty(),
        emulation=make_emulation(),
    )
    assert classify(make_case(expected=expected), observation).status is status


def test_accepted_gap_passes_without_being_hidden():
    # `expect: blind` records a known, owned gap. It must not page anyone, and
    # it must still show up as BLIND in coverage.
    observation = Observation(detection=empty(), telemetry=empty(), emulation=make_emulation())
    outcome = classify(make_case(expected=Outcome.BLIND), observation)
    assert outcome.status is CaseStatus.PASS
    assert outcome.outcome is Outcome.BLIND
    assert outcome.outcome.gap_kind == "visibility"


# ------------------------------------------------------------------ latency


def test_latency_is_measured_from_the_start_of_the_behaviour():
    emulation = make_emulation()
    observation = Observation(
        detection=result(1, offset=42.0, anchor=emulation.started_at),
        telemetry=result(1),
        emulation=emulation,
    )
    outcome = classify(make_case(), observation)
    assert outcome.latency_seconds == pytest.approx(42.0, abs=0.01)


def test_latency_breach_is_flagged():
    emulation = make_emulation()
    observation = Observation(
        detection=result(1, offset=400.0, anchor=emulation.started_at),
        telemetry=result(1),
        emulation=emulation,
    )
    outcome = classify(make_case(max_latency=300.0), observation)
    assert outcome.breached_latency
    assert "budget" in " ".join(outcome.notes)


def test_negative_latency_is_discarded():
    # Windows are padded before the behaviour to absorb clock skew, so a match
    # that predates it matched something else and is not a latency.
    emulation = make_emulation()
    observation = Observation(
        detection=result(1, offset=-90.0, anchor=emulation.started_at),
        telemetry=result(1),
        emulation=emulation,
    )
    assert classify(make_case(), observation).latency_seconds is None


# -------------------------------------------------------------------- noise


def test_baseline_hits_mark_a_rule_noisy_without_changing_the_outcome():
    emulation = make_emulation()
    observation = Observation(
        detection=result(1, anchor=emulation.started_at),
        telemetry=result(4),
        baseline=result(3),
        emulation=emulation,
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.DETECTED
    assert outcome.is_noisy
    assert outcome.baseline_hits == 3
    assert "quiet baseline window" in " ".join(outcome.notes)


def test_failed_baseline_query_does_not_mark_the_rule_noisy():
    observation = Observation(
        detection=result(1),
        telemetry=result(1),
        baseline=QueryResult.failed("timeout"),
        emulation=make_emulation(),
    )
    outcome = classify(make_case(), observation)
    assert not outcome.is_noisy
    assert "baseline query failed" in " ".join(outcome.notes)


# --------------------------------------------------------------- confidence


def test_truncation_degrades_confidence():
    observation = Observation(
        detection=result(3, truncated=True), telemetry=result(9), emulation=make_emulation()
    )
    assert classify(make_case(), observation).confidence is Confidence.MEDIUM


def test_replay_is_medium_confidence():
    observation = Observation(
        detection=result(1), telemetry=result(1), emulation=make_emulation(mode="replay")
    )
    assert classify(make_case(), observation).confidence is Confidence.MEDIUM


def test_live_execution_is_high_confidence():
    observation = Observation(
        detection=result(1),
        telemetry=result(1),
        emulation=make_emulation(mode="local", executed=True),
    )
    assert classify(make_case(), observation).confidence is Confidence.HIGH


def test_nonzero_exit_code_is_noted_but_not_fatal():
    emulation = make_emulation(mode="local", executed=True, exit_code=1)
    observation = Observation(
        detection=result(1, anchor=emulation.started_at),
        telemetry=result(1),
        emulation=emulation,
    )
    outcome = classify(make_case(), observation)
    assert outcome.outcome is Outcome.DETECTED
    assert "may have been blocked" in " ".join(outcome.notes)


# --------------------------------------------------------------- redaction


def test_redaction_replaces_matching_field_names():
    rows = [{"CommandLine": "x", "svc_Password": "hunter2", "Token": "abc"}]
    cleaned = redact(rows, ["password", "token"])
    assert cleaned[0]["CommandLine"] == "x"
    assert cleaned[0]["svc_Password"] == "[redacted]"
    assert cleaned[0]["Token"] == "[redacted]"


def test_redaction_is_applied_to_stored_evidence():
    emulation = make_emulation()
    events = [Event(raw={"CommandLine": "net use", "password": "hunter2"})]
    observation = Observation(
        detection=QueryResult(events=events, total=1),
        telemetry=result(1),
        emulation=emulation,
    )
    outcome = classify(make_case(), observation, redact_fields=["password"])
    assert outcome.evidence[0]["password"] == "[redacted]"


def test_evidence_can_be_disabled_entirely():
    observation = Observation(detection=result(3), telemetry=result(3), emulation=make_emulation())
    outcome = classify(make_case(), observation, store_evidence=False)
    assert outcome.evidence == []
