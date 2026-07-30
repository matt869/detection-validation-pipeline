"""The fixture backend - the thing that makes offline validation credible."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from harness.backends import BASELINE_TEST_ID, build_backend
from harness.backends.fixture import FixtureBackend, FixtureCorpus
from harness.core.config import BackendConfig
from harness.core.errors import BackendError
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, utcnow
from rulekit.compilers import CompiledQuery

EVENTS = [
    {"_test": "test-a", "_offset": 5, "Channel": "Sysmon", "EventID": 1, "Image": "a.exe"},
    {"_test": "test-a", "_offset": 60, "Channel": "Sysmon", "EventID": 1, "Image": "b.exe"},
    {"_test": "test-b", "_offset": 3, "Channel": "Sysmon", "EventID": 1, "Image": "c.exe"},
    {"_test": "__baseline__", "_offset": 120, "Channel": "Sysmon", "EventID": 1, "Image": "d.exe"},
]


@pytest.fixture
def corpus_root(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "manifest.yml").write_text(
        "scenario: scenario\ntests: [test-a, test-b]\n", encoding="utf-8"
    )
    (scenario / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in EVENTS) + "\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def backend(corpus_root) -> FixtureBackend:
    config = BackendConfig(name="fixture", kind="fixture", options={"path": str(corpus_root)})
    return FixtureBackend(config, root=corpus_root).load()


def match_all() -> CompiledQuery:
    return CompiledQuery(dialect="fixture", kind="detection", text="all", payload=lambda e: True)


def match_image(name: str) -> CompiledQuery:
    return CompiledQuery(
        dialect="fixture",
        kind="detection",
        text=f"Image={name}",
        payload=lambda e: e.get("Image") == name,
    )


# ------------------------------------------------------------------ loading


def test_corpus_loads_events_and_tests(corpus_root):
    corpus = FixtureCorpus.load(corpus_root / "scenario")
    assert len(corpus.events) == 4
    assert corpus.test_ids() == {"test-a", "test-b"}


def test_missing_corpus_directory_is_an_error(tmp_path):
    config = BackendConfig(name="fixture", kind="fixture", options={"path": "nope"})
    with pytest.raises(BackendError, match="not found"):
        FixtureBackend(config, root=tmp_path).load()


def test_malformed_jsonl_names_the_line(tmp_path):
    scenario = tmp_path / "broken"
    scenario.mkdir()
    (scenario / "events.jsonl").write_text('{"ok": 1}\nnot json\n', encoding="utf-8")
    config = BackendConfig(name="fixture", kind="fixture", options={"path": str(tmp_path)})
    with pytest.raises(BackendError, match="events.jsonl:2"):
        FixtureBackend(config, root=tmp_path).load()


# -------------------------------------------------------------- anchoring


def test_without_anchors_nothing_is_returned(backend):
    # An unanchored corpus has no place on the run's timeline.
    window = TimeWindow.last(3600)
    assert backend.search(match_all(), window).count == 0


def test_offsets_are_rebased_onto_the_current_run(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now}, baseline=now - timedelta(hours=1))
    window = TimeWindow(now - timedelta(seconds=10), now + timedelta(seconds=120))

    result = backend.search(match_all(), window, attribution="test-a")
    assert result.count == 2
    offsets = sorted(round((e.timestamp - now).total_seconds()) for e in result.events)
    assert offsets == [5, 60]


def test_events_outside_the_window_are_excluded(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now})
    narrow = TimeWindow(now, now + timedelta(seconds=30))
    assert backend.search(match_all(), narrow, attribution="test-a").count == 1


def test_attribution_prevents_cross_test_contamination(backend):
    # Padded windows overlap while tests run seconds apart; without attribution
    # every rule would see every other test's telemetry.
    now = utcnow()
    backend.set_anchors({"test-a": now, "test-b": now + timedelta(seconds=2)})
    window = TimeWindow(now - timedelta(minutes=5), now + timedelta(minutes=5))

    assert backend.search(match_all(), window, attribution="test-a").count == 2
    assert backend.search(match_all(), window, attribution="test-b").count == 1
    # Unattributed sees both, which is exactly the failure mode being prevented.
    assert backend.search(match_all(), window).count == 3


def test_baseline_events_use_the_baseline_anchor(backend):
    now = utcnow()
    baseline_start = now - timedelta(hours=1)
    backend.set_anchors({"test-a": now}, baseline=baseline_start)
    window = TimeWindow(baseline_start, now)

    result = backend.search(match_all(), window, attribution=BASELINE_TEST_ID)
    assert result.count == 1
    assert result.events[0].get("Image") == "d.exe"


def test_baseline_and_emulation_windows_do_not_overlap(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now}, baseline=now - timedelta(hours=1))
    emulation_window = TimeWindow(now - timedelta(minutes=2), now + timedelta(minutes=5))
    assert (
        backend.search(match_all(), emulation_window, attribution=BASELINE_TEST_ID).count == 0
    )


# ------------------------------------------------------------------ results


def test_predicate_filters_events(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now})
    window = TimeWindow(now - timedelta(minutes=1), now + timedelta(minutes=5))
    assert backend.search(match_image("b.exe"), window, attribution="test-a").count == 1


def test_no_results_is_not_an_error(backend):
    # Zero events is a meaningful answer - it is how BLIND gets detected.
    now = utcnow()
    backend.set_anchors({"test-a": now})
    result = backend.search(match_image("nope.exe"), TimeWindow.last(600), attribution="test-a")
    assert result.ok
    assert result.count == 0
    assert not result


def test_truncation_is_reported(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now})
    window = TimeWindow(now - timedelta(minutes=1), now + timedelta(minutes=5))
    result = backend.search(match_all(), window, attribution="test-a", limit=1)
    assert result.truncated
    assert result.total == 2
    assert len(result.events) == 1


def test_results_are_time_ordered(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now})
    window = TimeWindow(now - timedelta(minutes=1), now + timedelta(minutes=5))
    events = backend.search(match_all(), window, attribution="test-a").events
    assert events == sorted(events, key=lambda e: e.timestamp)


def test_a_raising_predicate_does_not_abort_the_query(backend):
    now = utcnow()
    backend.set_anchors({"test-a": now})

    def explode(event: Event) -> bool:
        raise RuntimeError("bad predicate")

    query = CompiledQuery(dialect="fixture", kind="detection", text="x", payload=explode)
    result = backend.search(query, TimeWindow.last(600), attribution="test-a")
    assert result.ok
    assert result.count == 0


def test_non_callable_payload_is_a_query_error(backend):
    query = CompiledQuery(dialect="fixture", kind="detection", text="x", payload="a string")
    result = backend.search(query, TimeWindow.last(600))
    assert not result.ok
    assert "predicate" in result.error


# -------------------------------------------------------------- health/etc


def test_health_reports_the_corpora(backend):
    status = backend.health()
    assert status.ok
    assert "test-a" in status.details["tests"]


def test_scenario_filter_limits_what_is_loaded(corpus_root):
    config = BackendConfig(name="fixture", kind="fixture", options={"path": str(corpus_root)})
    backend = FixtureBackend(config, root=corpus_root, scenarios=["other"]).load()
    assert backend.corpora == []


def test_factory_builds_the_configured_backend(settings):
    with build_backend(settings, "fixture") as backend:
        assert backend.dialect == "fixture"


def test_shipped_corpora_load(workspace, settings):
    with build_backend(settings, "fixture") as backend:
        status = backend.health()
    assert status.ok
    # Every test with recorded events must exist in the emulation catalogue.
    unknown = set(status.details["tests"]) - set(workspace.tests.ids())
    assert unknown == set()
