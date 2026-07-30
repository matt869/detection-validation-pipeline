"""Backend interface.

A backend is the only part of the pipeline that talks to a telemetry platform.
It receives an already-compiled query and a time window, and returns events. It
does not know what a rule is, what an outcome is, or why it is being asked -
which is what keeps the classifier testable without a SIEM.

Two rules every implementation must honour:

* **Never raise for "no results".** Zero events is a meaningful answer; it is
  how ``BLIND`` gets detected. Raise only when the *query itself* failed.
* **Report truncation.** A capped result set must set ``truncated`` so the
  classifier can degrade confidence rather than reporting a latency computed
  from an arbitrary subset.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from harness.core.config import BackendConfig
from harness.core.models import Event
from harness.core.timeutil import TimeWindow
from rulekit.compilers import CompiledQuery

__all__ = ["Backend", "HealthStatus", "QueryResult"]


@dataclass(slots=True)
class QueryResult:
    """Everything one query returned."""

    events: list[Event] = field(default_factory=list)
    #: Total matches the platform reports, which may exceed ``len(events)``.
    total: int = 0
    truncated: bool = False
    duration_seconds: float = 0.0
    query: str = ""
    backend: str = ""
    error: str | None = None

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)

    def __bool__(self) -> bool:
        """True when the query matched something. Errors are falsy."""
        return self.error is None and bool(self.events)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def count(self) -> int:
        """Best available match count, preferring the platform's own total."""
        return max(self.total, len(self.events))

    def earliest(self) -> datetime | None:
        stamps = [e.timestamp for e in self.events if e.timestamp is not None]
        return min(stamps) if stamps else None

    def sample(self, limit: int, fields: Sequence[str] | None = None) -> list[dict[str, Any]]:
        """The first ``limit`` events projected to ``fields``, for report evidence."""
        return [event.summary(fields) for event in self.events[:limit]]

    @classmethod
    def failed(cls, message: str, *, query: str = "", backend: str = "") -> QueryResult:
        return cls(error=message, query=query, backend=backend)


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Result of a backend reachability check."""

    name: str
    ok: bool
    message: str = ""
    latency_seconds: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "message": self.message,
            "latency_seconds": self.latency_seconds,
            "details": dict(self.details),
        }


class Backend(ABC):
    """Base class for telemetry platforms."""

    #: Query dialect this backend consumes. Must match a rulekit compiler.
    dialect: str = "fixture"

    def __init__(self, config: BackendConfig) -> None:
        self.config = config
        self.name = config.name

    # -- required ----------------------------------------------------------

    @abstractmethod
    def search(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        limit: int | None = None,
        attribution: str | None = None,
    ) -> QueryResult:
        """Run ``query`` over ``window`` and return matching events.

        ``attribution`` names the emulation test the caller is asking about.
        Backends that can attribute an event to a specific test should restrict
        results to it; live platforms generally cannot, and ignore it. This
        matters because search windows are padded for ingestion lag and clock
        skew, so consecutive tests overlap - without attribution, an offline
        replay would credit one rule with another test's telemetry.
        """

    @abstractmethod
    def health(self) -> HealthStatus:
        """Check reachability and credentials without running a real search."""

    # -- optional ----------------------------------------------------------

    def count(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        attribution: str | None = None,
    ) -> int:
        """Match count only.

        The default runs a bounded search; platforms with a cheap count API
        should override. Used by the telemetry probe, which only needs to know
        whether the number is zero.
        """
        return self.search(query, window, limit=1, attribution=attribution).count

    def close(self) -> None:
        """Release connections. Always called, even on failure."""

    def __enter__(self) -> Backend:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<{type(self).__name__} name={self.name!r} dialect={self.dialect!r}>"

    # -- helpers for implementations ---------------------------------------

    @property
    def limit(self) -> int:
        return self.config.max_results

    def _resolved_limit(self, limit: int | None) -> int:
        return max(1, min(limit or self.limit, self.limit))
