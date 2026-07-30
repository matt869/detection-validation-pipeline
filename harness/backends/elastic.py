"""Elasticsearch / OpenSearch backend.

Queries are sent as ``query_string`` inside a bool filter alongside a range
clause on the configured time field. ``query_string`` is used rather than the
structured bool DSL so that the query recorded in the report is the same text an
analyst can paste into Kibana - reproducibility matters more here than the
marginal parsing cost.
"""

from __future__ import annotations

import time
from typing import Any

from harness.backends.base import Backend, HealthStatus, QueryResult
from harness.backends.http import build_client, describe_http_error, require_httpx
from harness.core.config import BackendConfig
from harness.core.logging import get_logger
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, to_iso
from rulekit.compilers import CompiledQuery

__all__ = ["ElasticBackend"]

log = get_logger("elastic")


class ElasticBackend(Backend):
    dialect = "elastic"

    def __init__(self, config: BackendConfig) -> None:
        super().__init__(config)
        self._client: Any | None = None

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = build_client(self.config, headers=self._headers())
        return self._client

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        api_key = self.config.option("api_key")
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        return headers

    def _auth_tuple(self) -> tuple[str, str] | None:
        username = self.config.option("username")
        password = self.config.option("password")
        if username and password and not self.config.option("api_key"):
            return (str(username), str(password))
        return None

    @property
    def index(self) -> str:
        return str(self.config.option("index", "logs-*"))

    @property
    def time_field(self) -> str:
        return self.config.time_field or "@timestamp"

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
        query_text = str(query.payload)

        body = {
            "size": cap,
            "track_total_hits": True,
            "sort": [{self.time_field: {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                self.time_field: {
                                    "gte": to_iso(window.start),
                                    "lte": to_iso(window.end),
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                        {
                            "query_string": {
                                "query": query_text,
                                "analyze_wildcard": True,
                                "default_operator": "AND",
                                # Case-insensitive to match Sigma semantics.
                                "case_insensitive": True,
                            }
                        },
                    ]
                }
            },
        }

        try:
            response = self.client.post(
                f"/{self.index}/_search",
                json=body,
                auth=self._auth_tuple(),
                params={"ignore_unavailable": "true"},
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            if not isinstance(exc, (httpx.HTTPError, ValueError)):
                raise
            return QueryResult.failed(
                describe_http_error(exc) if isinstance(exc, httpx.HTTPError) else str(exc),
                query=query_text,
                backend=self.name,
            )

        hits = (payload.get("hits") or {}).get("hits") or []
        total_block = (payload.get("hits") or {}).get("total")
        total = total_block.get("value", len(hits)) if isinstance(total_block, dict) else len(hits)

        events = [
            Event(raw={**(hit.get("_source") or {}), "_id": hit.get("_id")}, source=self.name)
            for hit in hits
        ]
        return QueryResult(
            events=events,
            total=int(total),
            truncated=int(total) > len(events),
            duration_seconds=time.perf_counter() - started,
            query=query_text,
            backend=self.name,
        )

    def count(
        self,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        attribution: str | None = None,
    ) -> int:
        """``_count`` avoids transferring documents for the telemetry probe."""
        httpx = require_httpx()
        query_text = str(query.payload)
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                self.time_field: {
                                    "gte": to_iso(window.start),
                                    "lte": to_iso(window.end),
                                }
                            }
                        },
                        {"query_string": {"query": query_text, "default_operator": "AND"}},
                    ]
                }
            }
        }
        try:
            response = self.client.post(
                f"/{self.index}/_count",
                json=body,
                auth=self._auth_tuple(),
                params={"ignore_unavailable": "true"},
            )
            response.raise_for_status()
            return int(response.json().get("count", 0))
        except Exception as exc:
            if not isinstance(exc, (httpx.HTTPError, ValueError)):
                raise
            log.warning("count failed, falling back to search: %s", exc)
            return self.search(query, window, limit=1).count

    def health(self) -> HealthStatus:
        httpx = require_httpx()
        started = time.perf_counter()
        try:
            response = self.client.get("/", auth=self._auth_tuple())
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            if not isinstance(exc, (httpx.HTTPError, ValueError)):
                raise
            message = describe_http_error(exc) if isinstance(exc, httpx.HTTPError) else str(exc)
            return HealthStatus(name=self.name, ok=False, message=message)

        version = (payload.get("version") or {}).get("number", "unknown")
        distribution = (payload.get("version") or {}).get("distribution", "elasticsearch")
        return HealthStatus(
            name=self.name,
            ok=True,
            message=f"{distribution} {version}",
            latency_seconds=time.perf_counter() - started,
            details={"index": self.index, "time_field": self.time_field},
        )
