"""Per-host telemetry heartbeat: is each log source still arriving?

The validation pipeline answers "did the telemetry arrive *during this test
window*". That question only gets asked when a run happens. A forwarder that
dies at 02:00 on a Tuesday is invisible until the next scheduled validation,
and on most estates the first thing anyone learns about it is a detection that
did not fire during an incident.

This module answers the continuous version of the same question: for one log
source, when did each host last send anything, and has it stopped? It is
deliberately not a rule and not a detection - it needs no ATT&CK mapping, no
emulation test, and no expectation. A host either sent or it did not.

Three states, and the middle one is the point:

``alive``
    Last seen within the source's expected interval.
``late``
    Overdue, but inside the grace multiplier. Endpoints reboot, laptops close,
    batch sources arrive in clumps. Paging on the first missed interval trains
    people to ignore the alert, which costs more than the delay.
``silent``
    Past the grace window, or never seen at all. This is a visibility gap that
    nothing else in the pipeline would notice until the next validation run.

"Never seen" and "stopped" are both ``silent`` but they are different work:
one is an onboarding that never completed, the other is a regression. The
report keeps them apart with ``last_seen is None``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from harness.core.timeutil import to_utc

__all__ = [
    "Beat",
    "HeartbeatReport",
    "Observation",
    "build_heartbeat",
    "matches_scope",
]

#: Used when a source declares no interval of its own. Fifteen minutes is short
#: enough to catch a dead forwarder within a shift and long enough that a
#: quiet workstation does not alert every lunchtime.
DEFAULT_INTERVAL_SECONDS = 900.0
#: Overdue by this many intervals before a host is called silent.
DEFAULT_GRACE = 3.0


@dataclass(frozen=True, slots=True)
class Observation:
    """One event's contribution to a heartbeat: who sent it, and when."""

    host: str
    at: datetime


@dataclass(frozen=True, slots=True)
class Beat:
    """The heartbeat of one host for one source."""

    host: str
    source: str
    last_seen: datetime | None
    events: int
    age_seconds: float | None
    state: str
    interval_seconds: float

    @property
    def never_seen(self) -> bool:
        return self.last_seen is None

    @property
    def silent(self) -> bool:
        return self.state == "silent"

    def describe(self) -> str:
        if self.never_seen:
            return f"{self.host}: never sent {self.source}"
        return f"{self.host}: {self.source} last seen {format_age(self.age_seconds)} ago"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "source": self.source,
            "last_seen": self.last_seen.isoformat().replace("+00:00", "Z")
            if self.last_seen
            else None,
            "events": self.events,
            "age_seconds": round(self.age_seconds, 1) if self.age_seconds is not None else None,
            "state": self.state,
            "interval_seconds": self.interval_seconds,
            "never_seen": self.never_seen,
        }


@dataclass(slots=True)
class HeartbeatReport:
    as_of: datetime
    beats: list[Beat] = field(default_factory=list)

    def silent(self) -> list[Beat]:
        return [b for b in self.beats if b.state == "silent"]

    def late(self) -> list[Beat]:
        return [b for b in self.beats if b.state == "late"]

    def alive(self) -> list[Beat]:
        return [b for b in self.beats if b.state == "alive"]

    @property
    def healthy(self) -> bool:
        """False when any host has stopped. Late is not unhealthy; silent is."""
        return not self.silent()

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of.isoformat().replace("+00:00", "Z"),
            "healthy": self.healthy,
            "counts": {
                "alive": len(self.alive()),
                "late": len(self.late()),
                "silent": len(self.silent()),
            },
            "beats": [b.to_dict() for b in self.beats],
        }


def matches_scope(document: Mapping[str, Any], scope: Mapping[str, Any]) -> bool:
    """Does this event belong to the source described by ``scope``?

    The fixture dialect expresses a source as plain field equality, which is
    the same definition the telemetry probe compiles from - so a heartbeat can
    never disagree with the probe about what counts as "this log source".
    Values are compared as strings because a recorded ``EventID`` is as likely
    to be ``1`` as ``"1"``.
    """
    for key, expected in scope.items():
        actual = document.get(key)
        if actual is None:
            return False
        candidates = expected if isinstance(expected, (list, tuple)) else [expected]
        if not any(str(actual) == str(candidate) for candidate in candidates):
            return False
    return True


def observe_corpora(corpora: Iterable[Any], scope: Mapping[str, Any]) -> list[Observation]:
    """Observations for one source, read from recorded corpora.

    Offline by construction, which is the only way this is testable in CI - but
    it is also the honest demonstration. A corpus is a recording with a known
    start time, so "when did this host last send" has a real answer inside it.
    Against a live backend the same fold runs over query results instead; the
    arithmetic in :func:`build_heartbeat` does not change.

    A corpus with no ``recorded_at`` is skipped rather than guessed at. An
    invented anchor would produce ages that look authoritative and are not.
    """
    observations: list[Observation] = []
    for corpus in corpora:
        anchor = getattr(corpus, "recorded_at", None)
        if anchor is None:
            continue
        anchor = to_utc(anchor)
        for event in corpus.events:
            if not matches_scope(event.document, scope):
                continue
            host = _host_of(event.document)
            if not host:
                continue
            observations.append(
                Observation(host=host, at=anchor + timedelta(seconds=event.offset_seconds))
            )
    return observations


def hosts_in_corpora(corpora: Iterable[Any]) -> list[str]:
    """Every host that appears anywhere in the recordings.

    This is the closest thing to an inventory the offline corpora contain. It
    matters because a heartbeat that only reports hosts it has heard from can
    never report the host that never onboarded.
    """
    hosts: set[str] = set()
    for corpus in corpora:
        for event in corpus.events:
            host = _host_of(event.document)
            if host:
                hosts.add(host)
    return sorted(hosts)


def _host_of(document: Mapping[str, Any]) -> str:
    for key in ("_host", "Computer", "host", "hostname"):
        value = document.get(key)
        if value:
            return str(value)
    return ""


def build_heartbeat(
    observations: Iterable[Observation],
    *,
    source: str,
    as_of: datetime,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    grace: float = DEFAULT_GRACE,
    expected_hosts: Sequence[str] = (),
) -> HeartbeatReport:
    """Fold observations into one beat per host.

    ``expected_hosts`` is the inventory: hosts that should be sending this
    source. Without it a heartbeat can only report on hosts it has already
    heard from, which is precisely the wrong direction - the host that never
    onboarded is the one you most need named, and it contributes no events to
    notice it by.
    """
    as_of = to_utc(as_of)
    latest: dict[str, datetime] = {}
    counts: dict[str, int] = {}

    for observation in observations:
        moment = to_utc(observation.at)
        counts[observation.host] = counts.get(observation.host, 0) + 1
        if observation.host not in latest or moment > latest[observation.host]:
            latest[observation.host] = moment

    hosts = sorted(set(latest) | set(expected_hosts))
    silence_threshold = interval_seconds * grace

    beats: list[Beat] = []
    for host in hosts:
        last_seen = latest.get(host)
        if last_seen is None:
            age: float | None = None
            state = "silent"
        else:
            age = (as_of - last_seen).total_seconds()
            # A clock ahead of ours is not a dead host. Clamp rather than
            # produce a negative age that would read as "seen in the future".
            age = max(age, 0.0)
            if age <= interval_seconds:
                state = "alive"
            elif age <= silence_threshold:
                state = "late"
            else:
                state = "silent"

        beats.append(
            Beat(
                host=host,
                source=source,
                last_seen=last_seen,
                events=counts.get(host, 0),
                age_seconds=age,
                state=state,
                interval_seconds=interval_seconds,
            )
        )

    # Worst first: a report read at 3am should lead with what stopped.
    order = {"silent": 0, "late": 1, "alive": 2}
    beats.sort(key=lambda b: (order.get(b.state, 3), b.host))
    return HeartbeatReport(as_of=as_of, beats=beats)


def format_age(seconds: float | None) -> str:
    """Human-readable age, matching the console report's latency formatting."""
    if seconds is None:
        return "never"
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.0f}h"
    return f"{hours / 24:.0f}d"


def parse_interval(value: Any, default: float = DEFAULT_INTERVAL_SECONDS) -> float:
    from harness.core.timeutil import parse_duration

    return parse_duration(value, default=default) or default


def window_for(as_of: datetime, interval_seconds: float, grace: float) -> timedelta:
    """How far back a live query must look to decide anything useful."""
    return timedelta(seconds=interval_seconds * max(grace, 1.0) * 2)
