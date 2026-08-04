"""Capturing a live run as a replayable corpus.

The recorder exists so that evidence outlives the range that produced it. Two
properties matter more than any other, and both are tested here against the
real replayer rather than against an assertion about the file format:

* what it writes, the fixture backend can read back;
* what it writes has been through redaction first.

A recorder that quietly published production command lines to a public
repository would be a worse bug than any detection gap this project reports.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from harness.backends.fixture import BASELINE_TEST_ID, FixtureCorpus
from harness.core.errors import UsageError
from harness.core.models import Event
from harness.core.timeutil import TimeWindow
from harness.recorder import (
    CaptureWindow,
    capture,
    source_query,
    write_corpus,
)
from rulekit.telemetry import TelemetrySource

START = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)

SYSMON = TelemetrySource(
    id="sysmon_process_creation",
    name="Sysmon 1",
    backends={
        "splunk": {"scope": "index=windows EventCode=1"},
        "sentinel": {"table": "SysmonEvent", "scope": "EventID == 1"},
        "fixture": {"scope": {"EventID": 1}},
    },
)


class _Result:
    def __init__(self, events, *, error=None, truncated=False):
        self.events = events
        self.error = error
        self.truncated = truncated
        self.total = len(events)

    @property
    def ok(self):
        return self.error is None


class _Backend:
    """Enough of a backend to record from, without a SIEM."""

    dialect = "splunk"

    def __init__(self, results):
        self._results = results
        self.calls = []

    def search(self, query, window, *, limit=None, attribution=None):
        self.calls.append((query.text, window, limit))
        return self._results.pop(0) if self._results else _Result([])


def event(offset_seconds, **fields):
    document = {"Computer": "WKS-01", "EventID": 1, **fields}
    return Event(raw=document, timestamp=START + timedelta(seconds=offset_seconds))


def window_at(test_id="T1059.001-test", *, anchor=START, span=300):
    return CaptureWindow(
        test_id=test_id,
        window=TimeWindow(start=anchor, end=anchor + timedelta(seconds=span)),
        anchor=anchor,
    )


# ------------------------------------------------------------------ queries


def test_a_capture_query_is_built_from_the_source_selector():
    # The same selector that scopes rules and compiles the telemetry probe, so
    # a corpus cannot contain a different slice of the platform than the probe
    # measured.
    query = source_query(SYSMON, "splunk")
    assert query is not None
    assert query.text == "index=windows EventCode=1"
    assert query.metadata["source"] == "sysmon_process_creation"


def test_a_table_dialect_gets_its_table():
    query = source_query(SYSMON, "sentinel")
    assert query is not None
    assert query.text.startswith("SysmonEvent")
    assert "EventID == 1" in query.text


def test_a_dialect_with_no_selector_yields_no_query():
    assert source_query(SYSMON, "elastic") is None
    # The fixture selector is a mapping, not a query string - recording from a
    # replay would copy a corpus and call it evidence.
    assert source_query(SYSMON, "fixture") is None


# ----------------------------------------------------------------- capture


def test_events_are_attributed_and_offset_from_the_anchor():
    backend = _Backend([_Result([event(0), event(12)])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo")

    assert [e["_offset"] for e in corpus.events] == [0.0, 12.0]
    assert {e["_test"] for e in corpus.events} == {"T1059.001-test"}
    assert corpus.tests == ["T1059.001-test"]


def test_the_host_is_tagged_from_the_event():
    backend = _Backend([_Result([event(1)])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo")
    assert corpus.events[0]["_host"] == "WKS-01"
    assert corpus.hosts == {"WKS-01"}


def test_redaction_runs_before_anything_reaches_the_disk():
    backend = _Backend([_Result([event(1, CommandLine="psexec -p Hunter2")])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo", redact_fields=["commandline"])
    assert corpus.events[0]["CommandLine"] == "[redacted]"


def test_an_event_with_no_timestamp_is_dropped_not_anchored_to_zero():
    # Offset zero would invent a detection at the instant the behaviour started.
    stamped = Event(raw={"Computer": "WKS-01"}, timestamp=None)
    backend = _Backend([_Result([stamped])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo")
    assert corpus.events == []


def test_a_source_with_no_selector_is_reported_not_silently_omitted():
    # A missing source replays as BLIND, which reads as an estate-wide
    # visibility gap rather than a hole in the recording.
    unmapped = TelemetrySource(id="ghost", name="Ghost", backends={})
    backend = _Backend([_Result([event(0)])])
    corpus = capture(backend, [SYSMON, unmapped], [window_at()], name="demo")
    assert any("ghost" in problem for problem in corpus.errors)


def test_a_truncated_capture_says_so():
    backend = _Backend([_Result([event(0)], truncated=True)])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo", limit=1)
    assert any("cap" in problem for problem in corpus.errors)


def test_a_failed_query_is_recorded_and_does_not_abort_the_capture():
    backend = _Backend([_Result([], error="search head unreachable"), _Result([event(3)])])
    corpus = capture(backend, [SYSMON], [window_at("a"), window_at("b", anchor=START)], name="demo")
    assert any("unreachable" in problem for problem in corpus.errors)
    assert len(corpus.events) == 1


def test_no_sources_is_an_error_not_an_empty_corpus():
    corpus = capture(_Backend([]), [], [window_at()], name="demo")
    assert corpus.errors


def test_events_are_ordered_by_test_then_offset():
    backend = _Backend([_Result([event(30), event(2)]), _Result([event(5)])])
    corpus = capture(
        backend,
        [SYSMON],
        [window_at("b-test"), window_at("a-test")],
        name="demo",
    )
    assert [(e["_test"], e["_offset"]) for e in corpus.events] == [
        ("a-test", 5.0),
        ("b-test", 2.0),
        ("b-test", 30.0),
    ]


# ------------------------------------------------------------------- write


def test_written_corpus_is_readable_by_the_replayer(tmp_path):
    """The property the whole feature rests on: what it writes, replay reads."""
    backend = _Backend([_Result([event(0), event(9)]), _Result([event(4)])])
    corpus = capture(
        backend,
        [SYSMON],
        [window_at("T1059.001-test"), CaptureWindow(BASELINE_TEST_ID, window_at().window, START)],
        name="live-smoke",
    )
    directory = write_corpus(corpus, tmp_path / "live-smoke", recorded_from="WKS-01")

    loaded = FixtureCorpus.load(directory)
    assert loaded.name == "live-smoke"
    assert loaded.recorded_at is not None
    assert len(loaded.events) == 3
    assert {e.test_id for e in loaded.events} == {"T1059.001-test", BASELINE_TEST_ID}
    assert sorted(e.offset_seconds for e in loaded.events) == [0.0, 4.0, 9.0]


def test_the_manifest_marks_a_recording_for_review(tmp_path):
    import yaml

    backend = _Backend([_Result([event(0)])])
    corpus = capture(backend, [SYSMON], [window_at()], name="live-smoke")
    directory = write_corpus(corpus, tmp_path / "live-smoke", run_id="run-1")

    manifest = yaml.safe_load((directory / "manifest.yml").read_text(encoding="utf-8"))
    assert manifest["origin"] == "recorded"
    assert manifest["review_required"] is True
    assert manifest["run_id"] == "run-1"


def test_writing_over_an_existing_corpus_is_refused(tmp_path):
    # A corpus is evidence with a date on it.
    backend = _Backend([_Result([event(0)]), _Result([event(0)])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo")
    write_corpus(corpus, tmp_path / "demo")

    with pytest.raises(UsageError, match="already exists"):
        write_corpus(corpus, tmp_path / "demo")

    write_corpus(corpus, tmp_path / "demo", overwrite=True)


def test_an_empty_capture_is_never_written(tmp_path):
    corpus = capture(_Backend([_Result([])]), [SYSMON], [window_at()], name="demo")
    with pytest.raises(UsageError, match="no events"):
        write_corpus(corpus, tmp_path / "demo")


def test_every_line_is_one_json_object(tmp_path):
    backend = _Backend([_Result([event(0), event(1)])])
    corpus = capture(backend, [SYSMON], [window_at()], name="demo")
    directory = write_corpus(corpus, tmp_path / "demo")

    lines = (directory / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(isinstance(json.loads(line), dict) for line in lines)


# -------------------------------------------------------------- shipped data


def test_shipped_corpora_are_not_marked_as_recorded(repo_root):
    """Everything committed here is synthetic, and SECURITY.md says so."""
    import yaml

    for manifest_path in (repo_root / "fixtures" / "runs").glob("*/manifest.yml"):
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        assert manifest.get("origin") != "recorded", (
            f"{manifest_path} came from a real estate and must be reviewed, "
            "not committed with the synthetic corpora"
        )
