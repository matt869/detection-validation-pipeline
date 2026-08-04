"""Capture a live run's telemetry as a replayable fixture corpus.

The offline corpora are what make this project runnable in CI forever, and
until now the only way to produce one was to hand-write JSONL with the right
``_test`` / ``_offset`` / ``_host`` attribution. Nobody does that twice, which
means the moment a range is torn down, the evidence it produced is gone and
rebuilding it later is a project of its own.

So: while a run is executing against a real platform, ask each declared
telemetry source what it saw during each emulation window, and write that out
as a corpus. What comes back is exactly the data the verdicts were drawn from,
which is the difference between "our detections work" and evidence.

Three things this deliberately does not do:

* **Guess at attribution.** An event is tagged with the emulation test whose
  window contains it. Live platforms carry no marker saying which test caused
  an event, so an event inside two overlapping windows belongs to the earlier
  one and nothing pretends otherwise - which is also why the harness paces
  tests apart with ``inter_test_delay``.
* **Trust itself with your data.** Recorded telemetry is real estate data:
  hostnames, usernames, command lines, sometimes credentials that should not
  have been on a command line in the first place. Redaction runs before
  anything reaches the disk, and the manifest marks the corpus as needing
  review before it is committed. A recorder that quietly published production
  logs to a public repository would be a worse bug than any detection gap.
* **Overwrite.** A corpus is evidence with a date on it. Recording over one
  destroys the run it documented, so an existing directory is an error unless
  the caller explicitly asked to replace it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from harness.analysis.classify import redact
from harness.analysis.heartbeat import host_of
from harness.backends.base import Backend
from harness.core.errors import UsageError
from harness.core.logging import get_logger
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, to_utc, utcnow
from harness.core.yamlio import dump_yaml
from rulekit.compilers import CompiledQuery
from rulekit.telemetry import TelemetryCatalog, TelemetrySource

__all__ = [
    "CaptureWindow",
    "RecordedCorpus",
    "capture",
    "source_query",
    "write_corpus",
]

log = get_logger("recorder")

#: Tag for events captured from the quiet baseline window. Matches the fixture
#: backend's own constant - the corpus has to speak the language the replayer
#: reads.
BASELINE_TEST_ID = "__baseline__"

#: Per source, per window. High enough to capture a noisy source's real volume,
#: low enough that a misconfigured query cannot pull a day of an index into a
#: git repository.
DEFAULT_LIMIT = 2000


@dataclass(frozen=True, slots=True)
class CaptureWindow:
    """One emulation test and the span its events should be looked for in."""

    test_id: str
    window: TimeWindow
    #: Offsets are measured from here, so a replay can place the events back on
    #: a new run's timeline. Normally the moment the behaviour started.
    anchor: datetime


@dataclass(slots=True)
class RecordedCorpus:
    """The captured result, before it is written."""

    name: str
    events: list[dict[str, Any]] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    recorded_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.events)


def source_query(source: TelemetrySource, dialect: str) -> CompiledQuery | None:
    """A query that selects everything this source produced, and nothing else.

    Built from the same ``backends.<dialect>.scope`` selector that scopes rules
    and compiles the telemetry probe. One definition, so a corpus can never
    contain a different slice of the platform than the probe measured.
    """
    scope = source.scope(dialect)
    if not scope or not isinstance(scope, str):
        return None

    table = source.table(dialect)
    text = f"{table}\n| where {scope}" if table else scope
    return CompiledQuery(
        dialect=dialect,
        kind="telemetry",
        text=text,
        rule_name=source.id,
        metadata={"source": source.id, "capture": True},
    )


def capture(
    backend: Backend,
    sources: Sequence[TelemetrySource],
    windows: Sequence[CaptureWindow],
    *,
    name: str,
    limit: int = DEFAULT_LIMIT,
    redact_fields: Sequence[str] = (),
) -> RecordedCorpus:
    """Query every source over every window and assemble a corpus."""
    corpus = RecordedCorpus(name=name, recorded_at=utcnow())
    if not sources:
        corpus.errors.append("no telemetry sources to capture - nothing was recorded")
        return corpus

    queries = [(source, source_query(source, backend.dialect)) for source in sources]
    unmapped = [source.id for source, query in queries if query is None]
    if unmapped:
        # Not fatal: a corpus missing one source is still evidence for the rest.
        # Silently omitting it would not be - a later replay would report BLIND
        # and blame the estate for a gap in the recording.
        corpus.errors.append(
            f"no {backend.dialect} selector for: {', '.join(sorted(unmapped))} - "
            "these sources are absent from the corpus and will replay as BLIND"
        )

    for capture_window in windows:
        for source, query in queries:
            if query is None:
                continue
            result = backend.search(query, capture_window.window, limit=limit)
            if not result.ok:
                corpus.errors.append(f"{source.id} during {capture_window.test_id}: {result.error}")
                continue
            if result.truncated:
                corpus.errors.append(
                    f"{source.id} during {capture_window.test_id}: hit the {limit} event "
                    "cap; the recording is incomplete and a replay will under-report volume"
                )

            for event in result.events:
                document = _document(event, capture_window, redact_fields)
                if document is None:
                    continue
                corpus.events.append(document)
                host = document.get("_host")
                if host:
                    corpus.hosts.add(str(host))

            if source.id not in corpus.sources:
                corpus.sources.append(source.id)

        if (
            capture_window.test_id != BASELINE_TEST_ID
            and capture_window.test_id not in corpus.tests
        ):
            corpus.tests.append(capture_window.test_id)

    # Deterministic order: by test, then by offset. A corpus that reorders on
    # every capture produces a diff nobody can review.
    corpus.events.sort(key=lambda d: (str(d.get("_test")), float(d.get("_offset", 0))))
    return corpus


def _document(
    event: Event,
    capture_window: CaptureWindow,
    redact_fields: Sequence[str],
) -> dict[str, Any] | None:
    timestamp = event.timestamp
    if timestamp is None:
        # Without a timestamp there is no offset, and without an offset the
        # event cannot be placed on a replay timeline. Dropping it is better
        # than anchoring it to zero and inventing a detection at t+0.
        return None

    raw = dict(event.raw)
    raw.pop("_time", None)
    cleaned = redact([raw], redact_fields)[0]

    offset = (to_utc(timestamp) - to_utc(capture_window.anchor)).total_seconds()
    document: dict[str, Any] = {
        "_test": capture_window.test_id,
        "_offset": round(offset, 3),
    }
    host = host_of(cleaned)
    if host:
        document["_host"] = host
    document.update(cleaned)
    return document


def write_corpus(
    corpus: RecordedCorpus,
    directory: Path,
    *,
    description: str = "",
    recorded_from: str = "",
    sensor: str = "",
    profile: str = "",
    run_id: str = "",
    overwrite: bool = False,
) -> Path:
    """Write the corpus to ``directory`` as ``manifest.yml`` + ``events.jsonl``."""
    if directory.exists() and any(directory.iterdir()) and not overwrite:
        raise UsageError(
            f"{directory} already exists and is not empty",
            hint="A corpus is evidence with a date on it. Choose another name, "
            "or pass --overwrite if you really mean to replace this recording.",
        )
    if not corpus.events:
        raise UsageError(
            "captured no events - refusing to write an empty corpus",
            hint="An empty corpus replays as BLIND for every rule, which reads "
            "as a visibility gap in the estate rather than an empty recording.",
        )

    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "scenario": corpus.name,
        "description": description
        or f"Recorded from a live {profile or 'validation'} run. Review before committing.",
        "recorded_at": (corpus.recorded_at or utcnow()).isoformat().replace("+00:00", "Z"),
        "recorded_from": recorded_from or ", ".join(sorted(corpus.hosts)) or "unknown",
        "sensor": sensor or ", ".join(corpus.sources),
        # The flag that keeps real telemetry out of a public repository by
        # accident. Nothing enforces it but a reviewer, which is the point:
        # this is a decision a person has to make.
        "origin": "recorded",
        "review_required": True,
        "run_id": run_id,
        "tests": list(corpus.tests),
    }

    (directory / "manifest.yml").write_text(dump_yaml(manifest), encoding="utf-8", newline="\n")
    with (directory / "events.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for document in corpus.events:
            handle.write(json.dumps(document) + "\n")

    log.info(
        "recorded %d event(s) from %d source(s) into %s",
        len(corpus.events),
        len(corpus.sources),
        directory,
    )
    return directory


def windows_for(
    emulation: Any,
    *,
    baseline: TimeWindow | None = None,
    pre_seconds: float = 0.0,
    post_seconds: float = 0.0,
) -> list[CaptureWindow]:
    """Capture windows from an emulation outcome, plus the baseline window.

    The baseline is captured too, and it matters more than it looks: without it
    a replay cannot measure whether a rule fires on quiet-period activity, and
    the corpus would make every rule look cleaner than it is.
    """
    windows: list[CaptureWindow] = []
    for test_id, result in getattr(emulation, "results", {}).items():
        window = emulation.window_for(test_id)
        if window is None or result.started_at is None:
            continue
        windows.append(
            CaptureWindow(
                test_id=test_id,
                window=window.widen(before=pre_seconds, after=post_seconds),
                anchor=result.started_at,
            )
        )
    if baseline is not None:
        windows.append(
            CaptureWindow(test_id=BASELINE_TEST_ID, window=baseline, anchor=baseline.start)
        )
    return windows


def sources_for(rules: Iterable[Any], catalog: TelemetryCatalog) -> list[TelemetrySource]:
    """Every telemetry source the selected rules depend on, deduplicated."""
    seen: dict[str, TelemetrySource] = {}
    for rule in rules:
        for source in catalog.resolve(rule.telemetry):
            seen.setdefault(source.id, source)
    return list(seen.values())
