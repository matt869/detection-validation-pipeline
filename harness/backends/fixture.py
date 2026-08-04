"""Offline backend that replays recorded telemetry.

This is the backend that makes the pipeline testable. A fixture corpus is a
directory of JSON Lines events, each tagged with the emulation test that
produced it and an offset in seconds from that test's start. At query time the
offsets are rebased onto the *current* run's emulation window, so an offline run
executed today produces the same three-state outcomes, and the same detection
latencies, as the day the corpus was recorded.

Because the fixture dialect compiles to a Python predicate rather than a query
string, evaluating a rule here uses exactly the semantics in
:mod:`rulekit.matcher` - the same code path the linter checks. An offline PASS
is therefore evidence about the rule's logic, though not about the SIEM's
ability to run the translated query. See ``docs/three-state-model.md`` for what
offline results can and cannot tell you.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from harness.backends.base import Backend, HealthStatus, QueryResult
from harness.core.config import BackendConfig
from harness.core.errors import BackendError
from harness.core.logging import get_logger
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, parse_ts, to_utc
from harness.core.yamlio import load_yaml
from rulekit.compilers import CompiledQuery

__all__ = ["BASELINE_TEST_ID", "FixtureBackend", "FixtureCorpus"]

log = get_logger("fixture")

#: Events tagged with this id are anchored to the baseline window instead of to
#: an emulation test. They represent normal estate activity and are how the
#: pipeline measures whether a rule fires on quiet-period noise.
BASELINE_TEST_ID = "__baseline__"

_TEST_KEY = "_test"
_OFFSET_KEY = "_offset"
_HOST_KEY = "_host"


@dataclass(slots=True)
class FixtureEvent:
    """A recorded event plus its anchoring metadata."""

    test_id: str
    offset_seconds: float
    document: dict[str, Any]
    source_file: Path | None = None

    def materialise(self, anchor: datetime) -> Event:
        """Produce a real :class:`Event` timestamped relative to ``anchor``."""
        moment = to_utc(anchor) + timedelta(seconds=self.offset_seconds)
        document = dict(self.document)
        document["_time"] = moment.isoformat().replace("+00:00", "Z")
        return Event(raw=document, timestamp=moment, source=self.test_id)


@dataclass(slots=True)
class FixtureCorpus:
    """One scenario directory: a manifest plus its recorded events."""

    name: str
    path: Path
    description: str = ""
    tests: tuple[str, ...] = ()
    events: list[FixtureEvent] = field(default_factory=list)
    #: When the recording was taken. Validation does not need this - it anchors
    #: events to the emulation that just ran - but anything asking a question
    #: about elapsed time, such as the telemetry heartbeat, needs to know when
    #: "offset 0" actually was.
    recorded_at: datetime | None = None

    @classmethod
    def load(cls, directory: Path) -> FixtureCorpus:
        manifest_path = directory / "manifest.yml"
        manifest = load_yaml(manifest_path, default={}) if manifest_path.exists() else {}
        recorded = manifest.get("recorded_at")
        corpus = cls(
            name=str(manifest.get("scenario") or directory.name),
            path=directory,
            description=str(manifest.get("description") or ""),
            tests=tuple(str(t) for t in (manifest.get("tests") or [])),
            recorded_at=parse_ts(recorded) if recorded else None,
        )

        for events_file in sorted(directory.glob("*.jsonl")):
            corpus.events.extend(_read_jsonl(events_file))

        return corpus

    def test_ids(self) -> set[str]:
        declared = set(self.tests)
        observed = {e.test_id for e in self.events if e.test_id != BASELINE_TEST_ID}
        return declared | observed


def _read_jsonl(path: Path) -> list[FixtureEvent]:
    events: list[FixtureEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            try:
                document = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise BackendError(
                    f"{path}:{line_number}: invalid JSON: {exc.msg}",
                    hint="Each line must be one complete JSON object.",
                ) from exc
            if not isinstance(document, dict):
                raise BackendError(f"{path}:{line_number}: expected a JSON object")

            events.append(
                FixtureEvent(
                    test_id=str(document.pop(_TEST_KEY, BASELINE_TEST_ID)),
                    offset_seconds=float(document.pop(_OFFSET_KEY, 0)),
                    document=document,
                    source_file=path,
                )
            )
    return events


class FixtureBackend(Backend):
    """Replays a fixture corpus as if it were a live telemetry platform."""

    dialect = "fixture"

    def __init__(
        self,
        config: BackendConfig,
        *,
        root: Path | None = None,
        scenarios: Iterable[str] | None = None,
    ) -> None:
        super().__init__(config)
        base = Path(config.option("path", "fixtures/runs"))
        self.root = base if base.is_absolute() else (root or Path.cwd()) / base
        self.scenarios = tuple(scenarios) if scenarios else None
        self.corpora: list[FixtureCorpus] = []
        self._anchors: dict[str, datetime] = {}
        self._baseline_anchor: datetime | None = None
        self._loaded = False

    # -- corpus management -------------------------------------------------

    def load(self) -> FixtureBackend:
        """Read every selected corpus from disk. Idempotent."""
        if self._loaded:
            return self
        if not self.root.exists():
            raise BackendError(
                f"fixture corpus directory not found: {self.root}",
                hint="Create it, or point backends.fixture.options.path at your corpora.",
            )

        for directory in sorted(p for p in self.root.iterdir() if p.is_dir()):
            if directory.name.startswith((".", "_")):
                continue
            if self.scenarios and directory.name not in self.scenarios:
                continue
            corpus = FixtureCorpus.load(directory)
            if corpus.events:
                self.corpora.append(corpus)

        self._loaded = True
        log.debug(
            "loaded %d fixture corpora (%d events)",
            len(self.corpora),
            sum(len(c.events) for c in self.corpora),
        )
        return self

    def set_anchors(
        self,
        anchors: Mapping[str, datetime],
        *,
        baseline: datetime | None = None,
    ) -> None:
        """Bind emulation test ids to the times they actually ran.

        Called by the pipeline after emulation. Without anchors the backend has
        no way to place recorded events on the run's timeline, and every query
        returns nothing.
        """
        self._anchors = {k: to_utc(v) for k, v in anchors.items()}
        self._baseline_anchor = to_utc(baseline) if baseline else None

    def known_tests(self) -> set[str]:
        self.load()
        return set().union(*(c.test_ids() for c in self.corpora)) if self.corpora else set()

    # -- Backend -----------------------------------------------------------

    def search(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        limit: int | None = None,
        attribution: str | None = None,
    ) -> QueryResult:
        started = time.perf_counter()
        self.load()

        predicate = query.payload
        if not callable(predicate):
            return QueryResult.failed(
                f"fixture backend needs a compiled predicate, got {type(predicate).__name__}",
                query=query.text,
                backend=self.name,
            )

        cap = self._resolved_limit(limit)
        matched: list[Event] = []
        total = 0

        for event in self._materialise(window, attribution):
            try:
                if not predicate(event):
                    continue
            except Exception as exc:
                log.warning("predicate raised on a fixture event: %s", exc)
                continue
            total += 1
            if len(matched) < cap:
                matched.append(event)

        matched.sort(key=lambda e: e.timestamp or window.start)
        return QueryResult(
            events=matched,
            total=total,
            truncated=total > len(matched),
            duration_seconds=time.perf_counter() - started,
            query=query.text,
            backend=self.name,
        )

    def health(self) -> HealthStatus:
        try:
            self.load()
        except BackendError as exc:
            return HealthStatus(name=self.name, ok=False, message=exc.message)

        events = sum(len(c.events) for c in self.corpora)
        if not self.corpora:
            return HealthStatus(
                name=self.name,
                ok=False,
                message=f"no fixture corpora under {self.root}",
            )
        return HealthStatus(
            name=self.name,
            ok=True,
            message=f"{len(self.corpora)} corpora, {events} events",
            latency_seconds=0.0,
            details={
                "root": str(self.root),
                "scenarios": [c.name for c in self.corpora],
                "tests": sorted(self.known_tests()),
            },
        )

    # -- internals ---------------------------------------------------------

    def _materialise(self, window: TimeWindow, attribution: str | None) -> Iterable[Event]:
        """Yield every recorded event that lands inside ``window``.

        Events whose test never ran in this execution are skipped entirely -
        they belong to a different scenario and must not leak into results.

        When ``attribution`` is given, only that test's events are considered.
        Search windows are padded by minutes to absorb ingestion lag while
        tests run seconds apart, so without this filter every rule would see
        every other test's telemetry.
        """
        for corpus in self.corpora:
            for fixture in corpus.events:
                if attribution is not None and fixture.test_id != attribution:
                    continue
                anchor = self._anchor_for(fixture.test_id)
                if anchor is None:
                    continue
                event = fixture.materialise(anchor)
                if window.contains(event.timestamp):
                    yield event

    def _anchor_for(self, test_id: str) -> datetime | None:
        if test_id == BASELINE_TEST_ID:
            return self._baseline_anchor
        return self._anchors.get(test_id)

    # -- authoring aid -----------------------------------------------------
