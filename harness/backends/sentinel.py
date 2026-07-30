"""Microsoft Sentinel / Log Analytics backend.

Queries go to the Log Analytics query API with an explicit ``timespan``, which
Kusto applies before the query body - cheaper and less error-prone than
injecting a ``TimeGenerated`` predicate into every compiled query.

Authentication expects a bearer token supplied through configuration (typically
``${ENV:AZURE_ACCESS_TOKEN}`` refreshed by the surrounding automation). Token
acquisition is deliberately out of scope: this tool should not be holding a
client secret.
"""

from __future__ import annotations

import time
from typing import Any

from harness.backends.base import Backend, HealthStatus, QueryResult
from harness.backends.http import build_client, describe_http_error, require_httpx
from harness.core.config import BackendConfig
from harness.core.errors import BackendError
from harness.core.logging import get_logger
from harness.core.models import Event
from harness.core.timeutil import TimeWindow, to_iso
from rulekit.compilers import CompiledQuery

__all__ = ["SentinelBackend"]

log = get_logger("sentinel")

_DEFAULT_ENDPOINT = "https://api.loganalytics.io"


class SentinelBackend(Backend):
    dialect = "sentinel"

    def __init__(self, config: BackendConfig) -> None:
        super().__init__(config)
        self._client: Any | None = None

    @property
    def workspace_id(self) -> str:
        return str(self.config.require("workspace_id"))

    @property
    def client(self) -> Any:
        if self._client is None:
            token = self.config.option("token")
            if not token:
                raise BackendError(
                    f"backend '{self.name}': no bearer token configured",
                    hint="Set backends.<name>.options.token to ${ENV:AZURE_ACCESS_TOKEN} "
                    "and refresh it with `az account get-access-token "
                    "--resource https://api.loganalytics.io`.",
                )
            if not self.config.option("url"):
                # build_client uses config.options['url'] as the base URL.
                self.config.options.setdefault("url", _DEFAULT_ENDPOINT)
            self._client = build_client(
                self.config,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

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
        kql = str(query.payload)
        if "| take " not in kql and "| limit " not in kql and "| summarize" not in kql:
            kql = f"{kql}\n| take {cap}"

        body = {
            "query": kql,
            # Kusto accepts an ISO-8601 interval; this scopes the query before
            # the body runs, so no TimeGenerated clause is needed.
            "timespan": f"{to_iso(window.start)}/{to_iso(window.end)}",
        }

        try:
            response = self.client.post(f"/v1/workspaces/{self.workspace_id}/query", json=body)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            if not isinstance(exc, (httpx.HTTPError, ValueError)):
                raise
            return QueryResult.failed(
                describe_http_error(exc) if isinstance(exc, httpx.HTTPError) else str(exc),
                query=kql,
                backend=self.name,
            )

        events = list(self._parse_tables(payload))
        return QueryResult(
            events=events,
            total=len(events),
            truncated=len(events) >= cap,
            duration_seconds=time.perf_counter() - started,
            query=kql,
            backend=self.name,
        )

    def health(self) -> HealthStatus:
        httpx = require_httpx()
        started = time.perf_counter()
        try:
            response = self.client.post(
                f"/v1/workspaces/{self.workspace_id}/query",
                json={"query": "print Probe = 1", "timespan": "PT5M"},
            )
            response.raise_for_status()
        except Exception as exc:
            if not isinstance(exc, httpx.HTTPError):
                raise
            return HealthStatus(name=self.name, ok=False, message=describe_http_error(exc))
        except BackendError as exc:
            return HealthStatus(name=self.name, ok=False, message=exc.message)

        return HealthStatus(
            name=self.name,
            ok=True,
            message=f"workspace {self.workspace_id[:8]}... reachable",
            latency_seconds=time.perf_counter() - started,
        )

    # -- internals ---------------------------------------------------------

    def _parse_tables(self, payload: dict[str, Any]) -> list[Event]:
        """Flatten the column/row response shape into dictionaries."""
        events: list[Event] = []
        for table in payload.get("tables") or []:
            columns = [str(c.get("name")) for c in table.get("columns") or []]
            for row in table.get("rows") or []:
                document = dict(zip(columns, row, strict=False))
                events.append(Event(raw=document, source=self.name))
        return events
