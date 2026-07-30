"""Splunk backend using the REST search-export endpoint.

``/services/search/jobs/export`` streams results as they are produced, which
matters here because the telemetry probe often needs only to know whether a
count is greater than zero - there is no reason to wait for a full job to
finalise.
"""

from __future__ import annotations

import json
import time
from typing import Any

from harness.backends.base import Backend, HealthStatus, QueryResult
from harness.backends.http import build_client, describe_http_error, require_httpx
from harness.core.config import BackendConfig
from harness.core.logging import get_logger
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, to_iso
from rulekit.compilers import CompiledQuery

__all__ = ["SplunkBackend"]

log = get_logger("splunk")


class SplunkBackend(Backend):
    dialect = "splunk"

    def __init__(self, config: BackendConfig) -> None:
        super().__init__(config)
        self._client: Any | None = None

    # -- connection --------------------------------------------------------

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = build_client(self.config, headers=self._auth_headers())
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        token = self.config.option("token")
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _auth_tuple(self) -> tuple[str, str] | None:
        username = self.config.option("username")
        password = self.config.option("password")
        if username and password:
            return (str(username), str(password))
        return None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # -- Backend -----------------------------------------------------------

    def search(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        limit: int | None = None,
        attribution: str | None = None,
    ) -> QueryResult:
        httpx = require_httpx()
        started = time.perf_counter()
        cap = self._resolved_limit(limit)
        spl = self._as_search(str(query.payload), cap)

        payload = {
            "search": spl,
            "output_mode": "json",
            "earliest_time": to_iso(window.start),
            "latest_time": to_iso(window.end),
            "exec_mode": "oneshot",
            "count": cap,
            # A run should never be blocked by another user's dispatch quota.
            "adhoc_search_level": self.config.option("search_level", "fast"),
        }

        try:
            response = self.client.post(
                "/services/search/jobs/export",
                data=payload,
                auth=self._auth_tuple(),
            )
            response.raise_for_status()
        except Exception as exc:
            if not isinstance(exc, httpx.HTTPError):
                raise
            return QueryResult.failed(
                describe_http_error(exc), query=spl, backend=self.name
            )

        events = list(self._parse_export(response.text, cap))
        return QueryResult(
            events=events,
            total=len(events),
            truncated=len(events) >= cap,
            duration_seconds=time.perf_counter() - started,
            query=spl,
            backend=self.name,
        )

    def count(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        attribution: str | None = None,
    ) -> int:
        """Use Splunk's own aggregation rather than pulling events back."""
        text = str(query.payload)
        if "| stats count" not in text:
            text = f"{text} | stats count"
        counting = CompiledQuery(
            dialect=self.dialect, kind=query.kind, text=text, payload=text
        )
        result = self.search(counting, window, limit=1)
        if not result.ok or not result.events:
            return 0
        raw = result.events[0].get("count")
        try:
            return int(raw)
        except (TypeError, ValueError):
            return len(result.events)

    def health(self) -> HealthStatus:
        httpx = require_httpx()
        started = time.perf_counter()
        try:
            response = self.client.get(
                "/services/server/info",
                params={"output_mode": "json"},
                auth=self._auth_tuple(),
            )
            response.raise_for_status()
        except Exception as exc:
            if not isinstance(exc, httpx.HTTPError):
                raise
            return HealthStatus(name=self.name, ok=False, message=describe_http_error(exc))

        version = "unknown"
        try:
            entries = response.json().get("entry") or []
            if entries:
                version = entries[0].get("content", {}).get("version", "unknown")
        except (ValueError, AttributeError, IndexError):
            pass

        return HealthStatus(
            name=self.name,
            ok=True,
            message=f"Splunk {version}",
            latency_seconds=time.perf_counter() - started,
        )

    # -- internals ---------------------------------------------------------

    def _as_search(self, spl: str, cap: int) -> str:
        """Prefix ``search`` and append a head cap when the query lacks them.

        A query that already pipes to a transforming command keeps its own
        shape; blindly appending ``| head`` would truncate an aggregation.
        """
        text = spl.strip()
        if not text.startswith(("search ", "|", "tstats", "from ")):
            text = f"search {text}"
        if "| stats" not in text and "| head" not in text:
            text = f"{text} | head {cap}"
        return text

    def _parse_export(self, body: str, cap: int) -> list[Event]:
        """Parse the newline-delimited JSON export stream."""
        events: list[Event] = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                continue
            document = envelope.get("result")
            if not isinstance(document, dict):
                continue
            # Splunk nests the original event under _raw when it is JSON.
            raw_text = document.get("_raw")
            if isinstance(raw_text, str) and raw_text.startswith("{"):
                try:
                    nested = json.loads(raw_text)
                    if isinstance(nested, dict):
                        document = {**nested, **{k: v for k, v in document.items() if k != "_raw"}}
                except json.JSONDecodeError:
                    pass
            events.append(Event(raw=document, source=self.name))
            if len(events) >= cap:
                break
        return events
