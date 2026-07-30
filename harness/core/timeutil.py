"""Timestamp and duration handling.

Everything inside the pipeline is timezone-aware UTC. Naive timestamps coming
from backends are *assumed* UTC and normalised on the way in, because a silent
local-time interpretation produces detection latencies that are wrong by hours.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_DURATION_RE = re.compile(r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s|m|h|d|w)?", re.IGNORECASE)
_UNIT_SECONDS = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}

# Epoch formats seen in the wild across Splunk / Elastic / Sentinel exports.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y %I:%M:%S %p",
)


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def to_utc(value: datetime) -> datetime:
    """Normalise a datetime to UTC, treating naive values as already-UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_ts(value: object) -> datetime | None:
    """Best-effort parse of a timestamp from a backend event.

    Accepts datetimes, ISO-8601 strings (including ``Z`` suffix), and epoch
    seconds/milliseconds as int, float, or numeric string. Returns ``None`` when
    the value cannot be interpreted rather than raising, because a single
    unparsable event should not abort an entire validation run.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))

    text = str(value).strip()
    if not text:
        return None

    # Numeric string -> epoch.
    try:
        return _from_epoch(float(text))
    except ValueError:
        pass

    normalised = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        return to_utc(datetime.fromisoformat(normalised))
    except ValueError:
        pass

    for fmt in _TS_FORMATS:
        try:
            return to_utc(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _from_epoch(number: float) -> datetime:
    """Interpret a number as epoch seconds, milliseconds, or microseconds."""
    if number > 1e17:  # nanoseconds
        number /= 1e9
    elif number > 1e14:  # microseconds
        number /= 1e6
    elif number > 1e11:  # milliseconds
        number /= 1e3
    return datetime.fromtimestamp(number, tz=UTC)


def to_iso(value: datetime | None) -> str | None:
    """Render a datetime as an RFC-3339 string with a ``Z`` suffix."""
    if value is None:
        return None
    return to_utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_duration(value: str | int | float | None, *, default: float | None = None) -> float:
    """Parse ``"90s"``, ``"5m"``, ``"1h30m"``, or a bare number into seconds.

    A bare number is interpreted as seconds. Raises ``ValueError`` for anything
    unparsable unless ``default`` is supplied.
    """
    if value is None:
        if default is None:
            raise ValueError("duration is required")
        return default
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)

    text = str(value).strip().lower()
    if not text:
        if default is None:
            raise ValueError("empty duration")
        return default

    total = 0.0
    matched_span = 0
    for match in _DURATION_RE.finditer(text):
        unit = (match.group("unit") or "s").lower()
        total += float(match.group("value")) * _UNIT_SECONDS[unit]
        matched_span += len(match.group(0))

    if matched_span != len(text.replace(" ", "")) or (total == 0 and "0" not in text):
        if default is not None:
            return default
        raise ValueError(f"cannot parse duration: {value!r}")
    return total


def format_duration(seconds: float | None) -> str:
    """Human-readable duration, e.g. ``2m 04s``. Used in reports and the CLI."""
    if seconds is None:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """A closed [start, end] search window, always UTC.

    Backends receive windows already widened by ingestion lag and jitter; the
    widening happens once, here, so every backend sees identical bounds.
    """

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", to_utc(self.start))
        object.__setattr__(self, "end", to_utc(self.end))
        if self.end < self.start:
            raise ValueError(f"window end {self.end} precedes start {self.start}")

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def widen(self, *, before: float = 0.0, after: float = 0.0) -> TimeWindow:
        """Return a window extended by ``before``/``after`` seconds."""
        return TimeWindow(
            start=self.start - timedelta(seconds=before),
            end=self.end + timedelta(seconds=after),
        )

    def contains(self, moment: datetime | None) -> bool:
        if moment is None:
            return False
        moment = to_utc(moment)
        return self.start <= moment <= self.end

    @classmethod
    def last(cls, seconds: float, *, now: datetime | None = None) -> TimeWindow:
        end = now or utcnow()
        return cls(start=end - timedelta(seconds=seconds), end=end)

    @classmethod
    def around(cls, moment: datetime, *, before: float, after: float) -> TimeWindow:
        moment = to_utc(moment)
        return cls(
            start=moment - timedelta(seconds=before),
            end=moment + timedelta(seconds=after),
        )

    def to_dict(self) -> dict[str, str]:
        return {"start": to_iso(self.start) or "", "end": to_iso(self.end) or ""}

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{to_iso(self.start)} .. {to_iso(self.end)}"
