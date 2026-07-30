"""Shared HTTP plumbing for the live backends.

``httpx`` is an optional dependency: the whole pipeline runs offline against the
fixture backend without it. Importing it lazily here means a missing package
produces one actionable message at the point of use instead of an ImportError
at start-up.
"""

from __future__ import annotations

import ssl
from typing import Any

from harness.core.config import BackendConfig
from harness.core.errors import BackendError

__all__ = ["build_client", "require_httpx"]


def require_httpx() -> Any:
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise BackendError(
            "live backends need the 'httpx' package",
            hint="pip install 'detection-validation-pipeline[live]'  "
            "(or use --backend fixture to run offline)",
        ) from exc
    return httpx


def build_client(config: BackendConfig, *, headers: dict[str, str] | None = None) -> Any:
    """Construct a configured ``httpx.Client`` for a backend.

    TLS verification is on by default and can only be disabled explicitly per
    backend - a validation pipeline that silently trusts any certificate would
    be reporting on data it cannot attribute.
    """
    httpx = require_httpx()

    verify: bool | ssl.SSLContext = True
    ca_bundle = config.option("ca_bundle")
    if ca_bundle:
        verify = ssl.create_default_context(cafile=str(ca_bundle))
    elif config.option("verify_tls", True) is False:
        verify = False

    return httpx.Client(
        base_url=str(config.option("url", "")).rstrip("/"),
        headers=headers or {},
        timeout=httpx.Timeout(config.timeout_seconds),
        verify=verify,
        follow_redirects=True,
    )


def describe_http_error(exc: Exception) -> str:
    """Turn an httpx exception into a message that says what to fix."""
    httpx = require_httpx()

    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        body = (exc.response.text or "")[:400].replace("\n", " ")
        if status in (401, 403):
            return f"HTTP {status}: authentication rejected - check the token/role. {body}"
        if status == 404:
            return f"HTTP 404: endpoint or index not found - check the URL and index name. {body}"
        return f"HTTP {status}: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"connection failed: {exc}"
    if isinstance(exc, httpx.TimeoutException):
        return f"request timed out after the configured timeout: {exc}"
    return f"{type(exc).__name__}: {exc}"
