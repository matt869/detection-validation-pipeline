"""Dashboard HTTP server.

Deliberately minimal: a routing table, a handler, and ``ThreadingHTTPServer``
from the standard library. It is a read-only view over the run database, and it
binds to localhost because it has no authentication and should never be exposed.

Routes:

    GET /                       runs index
    GET /run/<id>               one run in detail
    GET /rule/<name>            outcome history for one rule
    GET /rules                  the rule library with its latest outcome
    GET /coverage               ATT&CK coverage from the latest run
    GET /api/runs               JSON
    GET /api/run/<id>           JSON
    GET /api/coverage           JSON
    GET /healthz                liveness
"""

from __future__ import annotations

import json
import re
import webbrowser
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse

from harness.analysis.coverage import build_coverage
from harness.core.errors import ExitCode
from harness.core.logging import get_logger

__all__ = ["serve"]

log = get_logger("dashboard")

Route = tuple[re.Pattern[str], Callable[..., tuple[int, str, str]]]


def serve(
    workspace,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser: bool = False,
) -> int:
    """Run the dashboard until interrupted."""
    from dashboard.app.router import build_routes

    routes = build_routes(workspace)

    class Handler(BaseHTTPRequestHandler):
        server_version = "dvp-dashboard"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            path = unquote(urlparse(self.path).path)
            for pattern, view in routes:
                match = pattern.fullmatch(path)
                if match is None:
                    continue
                try:
                    status, content_type, body = view(*match.groups())
                except Exception as exc:
                    log.exception("view failed for %s", path)
                    status, content_type, body = (
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        "text/plain; charset=utf-8",
                        f"{type(exc).__name__}: {exc}",
                    )
                self._respond(status, content_type, body)
                return
            self._respond(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", f"no route for {path}")

        def _respond(self, status: int, content_type: str, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            # The dashboard renders data straight from the database; lock down
            # what the page is allowed to do with it.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; img-src data:",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s - %s", self.address_string(), fmt % args)

    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"dashboard on {url}  (ctrl-c to stop)")
    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return ExitCode.OK


def json_response(payload: Any) -> tuple[int, str, str]:
    return (
        HTTPStatus.OK,
        "application/json; charset=utf-8",
        json.dumps(payload, indent=2, default=str),
    )


def html_response(body: str, status: int = HTTPStatus.OK) -> tuple[int, str, str]:
    return (status, "text/html; charset=utf-8", body)


def coverage_for(run, workspace):
    return build_coverage(run, reference=workspace.attack, targets=workspace.targets)
