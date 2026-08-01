"""Telemetry heartbeat: per-host liveness for a log source.

The pipeline's own question - "did telemetry arrive during this test window" -
is only asked when a run happens. These tests cover the continuous version:
which hosts have stopped sending, measured between runs.

The boundaries matter more than the arithmetic. Calling a host silent one
second too early produces an alert that is wrong, and an alert that is wrong
twice is an alert nobody reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from harness.analysis.heartbeat import (
    Observation,
    build_heartbeat,
    format_age,
    matches_scope,
    observe_corpora,
)

NOW = datetime(2026, 5, 14, 12, 0, tzinfo=UTC)
INTERVAL = 900.0  # 15m
GRACE = 3.0  # silent after 45m


def beats_by_host(report):
    return {b.host: b for b in report.beats}


def report_for(*ages_in_seconds: float, expected_hosts=()):
    observations = [
        Observation(host=f"host{i}", at=NOW - timedelta(seconds=age))
        for i, age in enumerate(ages_in_seconds)
    ]
    return build_heartbeat(
        observations,
        source="sysmon_process_creation",
        as_of=NOW,
        interval_seconds=INTERVAL,
        grace=GRACE,
        expected_hosts=expected_hosts,
    )


# ------------------------------------------------------------------ scoping


def test_scope_matches_on_every_declared_field():
    document = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    assert matches_scope(document, {"Channel": "Microsoft-Windows-Sysmon/Operational"})
    assert matches_scope(
        document, {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    )
    assert not matches_scope(document, {"Channel": "Security"})


def test_scope_compares_as_strings():
    # A recorded EventID is as likely to be 1 as "1", and a heartbeat that
    # disagreed with the telemetry probe about that would be worse than useless.
    assert matches_scope({"EventID": 1}, {"EventID": "1"})
    assert matches_scope({"EventID": "1"}, {"EventID": 1})


def test_scope_accepts_a_list_of_alternatives():
    assert matches_scope({"EventID": 13}, {"EventID": [12, 13, 14]})
    assert not matches_scope({"EventID": 15}, {"EventID": [12, 13, 14]})


def test_a_missing_field_is_not_a_match():
    assert not matches_scope({"Channel": "Security"}, {"EventID": 1})


# -------------------------------------------------------------------- state


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (0, "alive"),
        (INTERVAL - 1, "alive"),
        (INTERVAL, "alive"),  # exactly on time is on time
        (INTERVAL + 1, "late"),
        (INTERVAL * GRACE, "late"),  # the grace window is inclusive
        (INTERVAL * GRACE + 1, "silent"),
    ],
)
def test_state_boundaries(age, expected):
    assert report_for(age).beats[0].state == expected


def test_late_is_not_unhealthy_but_silent_is():
    # Endpoints reboot and laptops close. Paging on the first missed interval
    # is how a liveness alert gets muted.
    assert report_for(INTERVAL * 2).healthy
    assert not report_for(INTERVAL * 4).healthy


def test_a_host_that_never_sent_is_silent_and_distinguishable():
    report = report_for(0, expected_hosts=["host0", "never-onboarded"])
    beats = beats_by_host(report)
    assert beats["never-onboarded"].state == "silent"
    assert beats["never-onboarded"].never_seen
    assert beats["never-onboarded"].events == 0
    # Stopped and never-started are both silent and are different work items.
    assert not beats["host0"].never_seen


def test_only_hosts_in_the_inventory_or_the_data_are_reported():
    # No inference: a host is reported because it sent something or because an
    # operator said it should. Guessing from a naming convention manufactures
    # gaps that are artefacts of the guess.
    report = report_for(0)
    assert [b.host for b in report.beats] == ["host0"]


def test_a_clock_ahead_of_ours_is_not_a_dead_host():
    report = build_heartbeat(
        [Observation(host="skewed", at=NOW + timedelta(minutes=5))],
        source="s",
        as_of=NOW,
        interval_seconds=INTERVAL,
        grace=GRACE,
    )
    assert report.beats[0].age_seconds == 0.0
    assert report.beats[0].state == "alive"


def test_the_worst_state_is_listed_first():
    report = report_for(0, INTERVAL * 2, INTERVAL * 10)
    assert [b.state for b in report.beats] == ["silent", "late", "alive"]


def test_last_seen_is_the_newest_event_not_the_first():
    report = build_heartbeat(
        [
            Observation(host="h", at=NOW - timedelta(hours=6)),
            Observation(host="h", at=NOW - timedelta(minutes=2)),
            Observation(host="h", at=NOW - timedelta(hours=3)),
        ],
        source="s",
        as_of=NOW,
        interval_seconds=INTERVAL,
        grace=GRACE,
    )
    beat = report.beats[0]
    assert beat.state == "alive"
    assert beat.events == 3


# ----------------------------------------------------------------- corpora


class _Event:
    def __init__(self, document, offset):
        self.document = document
        self.offset_seconds = offset


class _Corpus:
    def __init__(self, events, recorded_at=NOW):
        self.events = events
        self.recorded_at = recorded_at


def test_observations_are_anchored_to_the_recording_start():
    corpus = _Corpus([_Event({"_host": "h", "EventID": 1}, 120)])
    observations = observe_corpora([corpus], {"EventID": 1})
    assert observations == [Observation(host="h", at=NOW + timedelta(seconds=120))]


def test_a_corpus_without_a_recorded_at_is_skipped_not_guessed():
    # An invented anchor produces ages that look authoritative and are not.
    corpus = _Corpus([_Event({"_host": "h", "EventID": 1}, 0)], recorded_at=None)
    assert observe_corpora([corpus], {"EventID": 1}) == []


def test_events_with_no_host_are_ignored():
    corpus = _Corpus([_Event({"EventID": 1}, 0)])
    assert observe_corpora([corpus], {"EventID": 1}) == []


# ---------------------------------------------------------------- shipped


def test_the_shipped_corpora_produce_a_heartbeat(repo_root):
    from harness.backends.fixture import FixtureBackend
    from harness.core.config import load_settings

    settings = load_settings(root=repo_root)
    backend = FixtureBackend(settings.backend("fixture"), root=repo_root).load()

    observations = observe_corpora(
        backend.corpora, {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    )
    assert observations, "the corpora carry Sysmon process creation on several hosts"

    report = build_heartbeat(
        observations,
        source="sysmon_process_creation",
        as_of=max(o.at for o in observations),
        interval_seconds=INTERVAL,
        grace=GRACE,
    )
    # At least one host stopped before the recording ended - that is the whole
    # signal, and it comes out of the shipped data rather than a contrived case.
    assert report.silent()


def test_every_corpus_declares_when_it_was_recorded(repo_root):
    from harness.backends.fixture import FixtureBackend
    from harness.core.config import load_settings

    settings = load_settings(root=repo_root)
    backend = FixtureBackend(settings.backend("fixture"), root=repo_root).load()
    undated = [c.name for c in backend.corpora if c.recorded_at is None]
    assert undated == [], "a corpus with no recorded_at cannot answer any question about time"


# ------------------------------------------------------------------ format


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(None, "never"), (45, "45s"), (600, "10m"), (7200, "2h"), (86400 * 3, "3d")],
)
def test_age_formatting(seconds, expected):
    assert format_age(seconds) == expected
