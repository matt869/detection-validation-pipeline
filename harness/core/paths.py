"""Project layout resolution.

Every path in the pipeline is derived from a single project root so the tool
behaves identically whether it is invoked from the repo root, from ``tests/``,
or from an installed wheel pointed at a content directory via ``DVP_ROOT``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

#: Files whose presence identifies the project root.
_ROOT_MARKERS = ("pyproject.toml", ".dvp-root")


@lru_cache(maxsize=8)
def find_root(start: Path | None = None) -> Path:
    """Locate the project root.

    ``DVP_ROOT`` wins if set; otherwise walk up from ``start`` looking for a
    marker file. Falls back to the current working directory so the tool never
    hard-fails on layout detection alone.
    """
    override = os.environ.get("DVP_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if any((candidate / marker).exists() for marker in _ROOT_MARKERS):
            return candidate
    return current


@dataclass(frozen=True, slots=True)
class Layout:
    """Resolved directory layout. Construct via :func:`layout`."""

    root: Path

    @property
    def config(self) -> Path:
        return self.root / "config"

    @property
    def profiles(self) -> Path:
        return self.config / "profiles"

    @property
    def detections(self) -> Path:
        return self.root / "detections"

    @property
    def mapping(self) -> Path:
        return self.root / "mapping"

    @property
    def fixtures(self) -> Path:
        return self.root / "fixtures"

    @property
    def fixture_runs(self) -> Path:
        return self.fixtures / "runs"

    @property
    def baseline(self) -> Path:
        return self.root / "baseline"

    @property
    def baseline_profiles(self) -> Path:
        return self.baseline / "profiles"

    @property
    def docs(self) -> Path:
        return self.root / "docs"

    @property
    def results(self) -> Path:
        return self.docs / "results"

    @property
    def storage(self) -> Path:
        return self.root / "storage"

    @property
    def migrations(self) -> Path:
        return self.storage / "migrations"

    @property
    def scheduler(self) -> Path:
        return self.root / "scheduler"

    @property
    def var(self) -> Path:
        """Mutable state (database, caches). Git-ignored."""
        return self.root / ".dvp"

    def ensure_writable(self) -> None:
        """Create the directories the pipeline writes to."""
        for path in (self.var, self.results, self.fixture_runs):
            path.mkdir(parents=True, exist_ok=True)

    def relative(self, path: Path | str) -> str:
        """Render a path relative to the root for stable log/report output."""
        try:
            return str(Path(path).resolve().relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")


def layout(start: Path | None = None) -> Layout:
    return Layout(find_root(start))
