"""Identifier generation and slugging.

Run identifiers are sortable and human-readable so that
``ls fixtures/runs`` and ``ORDER BY run_id`` both produce chronological order.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
from datetime import datetime

from harness.core.timeutil import to_utc, utcnow

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def new_run_id(*, now: datetime | None = None) -> str:
    """``run-20260130T142233Z-9f21ac`` - lexicographically sortable by time."""
    stamp = to_utc(now or utcnow()).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}-{secrets.token_hex(3)}"


def new_case_id(run_id: str, rule_name: str, emulation_id: str) -> str:
    """Deterministic per-run case id, so re-running analysis is idempotent."""
    digest = stable_hash(f"{run_id}|{rule_name}|{emulation_id}", length=8)
    return f"case-{digest}"


def stable_hash(value: str, *, length: int = 12) -> str:
    """Truncated BLAKE2b hex digest. Stable across processes and platforms."""
    return hashlib.blake2b(value.encode("utf-8"), digest_size=32).hexdigest()[:length]


def slugify(value: str, *, max_length: int = 80) -> str:
    """Lowercase, hyphen-separated, ASCII-only identifier."""
    normalised = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    slug = _SLUG_STRIP.sub("-", normalised.lower()).strip("-")
    if len(slug) > max_length:
        slug = slug[:max_length].rstrip("-")
    return slug or "unnamed"


def content_fingerprint(payload: object) -> str:
    """Fingerprint of a rule's logic, used to detect meaningful rule changes.

    Metadata edits (description, author) deliberately do not change the
    fingerprint - only the detection logic does.
    """
    return stable_hash(_canonical(payload), length=16)


def _canonical(payload: object) -> str:
    """Deterministic textual encoding of nested dict/list/scalar structures."""
    if isinstance(payload, dict):
        inner = ",".join(f"{k}={_canonical(payload[k])}" for k in sorted(map(str, payload)))
        return "{" + inner + "}"
    if isinstance(payload, (list, tuple)):
        return "[" + ",".join(_canonical(item) for item in payload) + "]"
    if isinstance(payload, bool):
        return "true" if payload else "false"
    if payload is None:
        return "null"
    return str(payload)
