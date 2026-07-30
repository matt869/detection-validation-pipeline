"""Review dashboard.

A read-only view over the run database, served from the standard library. No
framework, no build step, no external assets - it starts with ``dvp dashboard``
on a laptop during a review meeting and needs nothing installed.

It binds to localhost by default and has no authentication, because it has no
business being exposed. See ``docs/threat-model.md``.
"""

from __future__ import annotations

__all__ = ["serve"]


def serve(*args, **kwargs):  # pragma: no cover - thin re-export
    from dashboard.app import serve as _serve

    return _serve(*args, **kwargs)
