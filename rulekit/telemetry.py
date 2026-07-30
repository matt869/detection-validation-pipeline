"""The telemetry source catalogue.

``mapping/telemetry_sources.yml`` names every log source the detection library
depends on and, for each backend, says how to select it. Two things fall out of
that one file:

* **Query scoping.** Compilers prefix a rule's detection logic with the source's
  selector, so a rule body never hardcodes ``index=`` or a KQL table name.
* **The telemetry probe.** The same selector, *without* the detection logic, is
  the query that answers "did this log source produce anything at all during
  the test window?" - the question that separates a ``VISIBLE`` detection gap
  from a ``BLIND`` visibility gap.

Because both come from one definition, a rule cannot silently search one index
while its blindness probe checks another.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.core.errors import ConfigError
from harness.core.yamlio import load_yaml

__all__ = ["TelemetryCatalog", "TelemetrySource"]


@dataclass(frozen=True, slots=True)
class TelemetrySource:
    """One named log source and its per-backend selectors."""

    id: str
    name: str
    platform: str = "any"
    provider: str = ""
    description: str = ""
    event_ids: tuple[str, ...] = ()
    #: Fields this source is expected to carry. The linter checks that rules
    #: only reference fields their declared sources actually provide.
    fields: tuple[str, ...] = ()
    #: Team accountable for the source being onboarded and healthy.
    owner: str = ""
    #: What to do when this source turns out to be blind.
    onboarding: str = ""
    #: backend kind -> {"scope": <selector>, "table": <optional table>}
    backends: dict[str, dict[str, Any]] = field(default_factory=dict)

    def scope(self, backend_kind: str) -> Any:
        """Selector for this source in a given dialect, or ``None`` if unmapped."""
        entry = self.backends.get(backend_kind)
        if not entry:
            return None
        return entry.get("scope")

    def table(self, backend_kind: str) -> str | None:
        entry = self.backends.get(backend_kind)
        return entry.get("table") if entry else None

    def supports(self, backend_kind: str) -> bool:
        return backend_kind in self.backends

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform,
            "provider": self.provider,
            "description": self.description,
            "event_ids": list(self.event_ids),
            "fields": list(self.fields),
            "owner": self.owner,
            "onboarding": self.onboarding,
            "backends": dict(self.backends),
        }

    @classmethod
    def from_dict(cls, source_id: str, data: Mapping[str, Any]) -> TelemetrySource:
        backends = data.get("backends") or {}
        if not isinstance(backends, Mapping):
            raise ConfigError(f"telemetry source '{source_id}': 'backends' must be a mapping")
        return cls(
            id=source_id,
            name=str(data.get("name") or source_id),
            platform=str(data.get("platform") or "any"),
            provider=str(data.get("provider") or ""),
            description=str(data.get("description") or ""),
            event_ids=tuple(str(e) for e in (data.get("event_ids") or [])),
            fields=tuple(str(f) for f in (data.get("fields") or [])),
            owner=str(data.get("owner") or ""),
            onboarding=str(data.get("onboarding") or ""),
            backends={str(k): dict(v or {}) for k, v in backends.items()},
        )


@dataclass(slots=True)
class TelemetryCatalog:
    """All known telemetry sources, keyed by id."""

    sources: dict[str, TelemetrySource] = field(default_factory=dict)
    path: Path | None = None

    def __iter__(self) -> Iterator[TelemetrySource]:
        return iter(self.sources.values())

    def __len__(self) -> int:
        return len(self.sources)

    def __contains__(self, source_id: object) -> bool:
        return str(source_id) in self.sources

    def get(self, source_id: str) -> TelemetrySource | None:
        return self.sources.get(source_id)

    def require(self, source_id: str) -> TelemetrySource:
        source = self.sources.get(source_id)
        if source is None:
            known = ", ".join(sorted(self.sources)) or "none"
            raise ConfigError(
                f"unknown telemetry source '{source_id}'",
                hint=f"Define it in mapping/telemetry_sources.yml. Known: {known}",
            )
        return source

    def resolve(self, source_ids: Any) -> list[TelemetrySource]:
        """Resolve a rule's ``telemetry:`` list, skipping unknown ids silently.

        Unknown ids are reported by the linter as an error; resolution itself
        stays permissive so one stale reference cannot break an entire run.
        """
        if isinstance(source_ids, str):
            source_ids = [source_ids]
        return [s for s in (self.sources.get(str(i)) for i in (source_ids or [])) if s]

    def for_platform(self, platform: str) -> list[TelemetrySource]:
        platform = platform.lower()
        return [s for s in self.sources.values() if s.platform.lower() in (platform, "any")]

    @classmethod
    def load(cls, path: Path | str) -> TelemetryCatalog:
        path = Path(path)
        document = load_yaml(path, default={}) or {}
        entries = document.get("sources", document)
        if not isinstance(entries, Mapping):
            raise ConfigError(f"{path}: expected a 'sources' mapping")
        return cls(
            sources={
                str(key): TelemetrySource.from_dict(str(key), value or {})
                for key, value in entries.items()
            },
            path=path,
        )

    @classmethod
    def empty(cls) -> TelemetryCatalog:
        return cls(sources={})
