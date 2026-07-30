"""Route table.

Each view opens its own short-lived database connection. SQLite in WAL mode
handles concurrent readers fine, and per-request connections keep the threaded
server from sharing a connection across threads - which SQLite does not allow.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from http import HTTPStatus

from dashboard.app import html_response, json_response
from dashboard.app.views import (
    render_coverage,
    render_error,
    render_index,
    render_rule,
    render_rules,
    render_run,
)
from harness.analysis.coverage import build_coverage

__all__ = ["build_routes"]


def build_routes(workspace) -> list[tuple[re.Pattern[str], Callable]]:
    def _latest_run():
        with workspace.store() as store:
            if not store.is_initialised():
                return None
            run_id = store.latest_run_id()
            return store.load_run(run_id) if run_id else None

    def _load(run_id: str):
        with workspace.store() as store:
            return store.load_run(run_id) if store.is_initialised() else None

    # -- HTML -----------------------------------------------------------

    def index():
        with workspace.store() as store:
            runs = store.list_runs(limit=50) if store.is_initialised() else []
        return html_response(render_index(runs, _latest_run()))

    def run_detail(run_id: str):
        run = _load(run_id)
        if run is None:
            return html_response(
                render_error(404, f"run '{run_id}' not found"), HTTPStatus.NOT_FOUND
            )
        return html_response(render_run(run, workspace))

    def rule_detail(name: str):
        with workspace.store() as store:
            history = store.rule_history(name) if store.is_initialised() else []
        return html_response(render_rule(name, history, workspace.rules.get(name)))

    def rules_index():
        with workspace.store() as store:
            outcomes = store.latest_outcomes() if store.is_initialised() else {}
        return html_response(render_rules(workspace, outcomes))

    def coverage_view():
        run = _latest_run()
        if run is None:
            return html_response(
                render_error(404, "no runs stored yet"), HTTPStatus.NOT_FOUND
            )
        return html_response(render_coverage(run, workspace))

    # -- JSON -----------------------------------------------------------

    def api_runs():
        with workspace.store() as store:
            runs = store.list_runs(limit=100) if store.is_initialised() else []
        return json_response([r.to_dict() for r in runs])

    def api_run(run_id: str):
        run = _load(run_id)
        if run is None:
            return (HTTPStatus.NOT_FOUND, "application/json", '{"error":"not found"}')
        return json_response(run.to_dict())

    def api_coverage():
        run = _latest_run()
        if run is None:
            return (HTTPStatus.NOT_FOUND, "application/json", '{"error":"no runs"}')
        coverage = build_coverage(
            run, reference=workspace.attack, targets=workspace.targets
        )
        return json_response(coverage.to_dict())

    def healthz():
        return (HTTPStatus.OK, "text/plain; charset=utf-8", "ok")

    return [
        (re.compile(r"/"), index),
        (re.compile(r"/run/([^/]+)"), run_detail),
        (re.compile(r"/rule/([^/]+)"), rule_detail),
        (re.compile(r"/rules"), rules_index),
        (re.compile(r"/coverage"), coverage_view),
        (re.compile(r"/api/runs"), api_runs),
        (re.compile(r"/api/run/([^/]+)"), api_run),
        (re.compile(r"/api/coverage"), api_coverage),
        (re.compile(r"/healthz"), healthz),
    ]
