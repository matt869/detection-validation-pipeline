"""Validation profiles.

A profile answers "what are we validating today?" - which rules, against which
emulation tests, on which backend, held to which gates. Profiles are the unit an
operator or a scheduler names, so they live in ``config/profiles/*.yml`` where
they can be reviewed like any other change.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.core.config import GateSettings, Settings, TimingSettings
from harness.core.errors import ConfigError
from harness.core.models import Severity
from harness.core.yamlio import iter_yaml_files, load_yaml

__all__ = ["Profile", "ProfileLibrary", "load_profiles"]


@dataclass(frozen=True, slots=True)
class Selector:
    """Which rules a profile covers."""

    rules: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    min_severity: Severity | None = None
    include_inactive: bool = False

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.rules,
                self.platforms,
                self.tactics,
                self.techniques,
                self.tags,
                self.statuses,
                self.min_severity,
            )
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> Selector:
        data = data or {}
        severity = data.get("min_severity")
        return cls(
            rules=_tuple(data.get("rules")),
            platforms=_tuple(data.get("platforms")),
            tactics=_tuple(data.get("tactics")),
            techniques=_tuple(data.get("techniques")),
            tags=_tuple(data.get("tags")),
            statuses=_tuple(data.get("statuses")),
            min_severity=Severity.parse(severity) if severity else None,
            include_inactive=bool(data.get("include_inactive", False)),
        )


@dataclass(slots=True)
class Profile:
    """One named validation scenario."""

    name: str
    description: str = ""
    backend: str | None = None
    select: Selector = field(default_factory=Selector)
    #: Rule names removed after selection.
    exclude_rules: tuple[str, ...] = ()
    #: Emulation tests to run. Empty means "whatever the selected rules declare".
    tests: tuple[str, ...] = ()
    #: Fixture corpora to load, for offline runs.
    scenarios: tuple[str, ...] = ()
    #: Per-profile overrides layered on top of settings.
    timing_overrides: dict[str, Any] = field(default_factory=dict)
    gate_overrides: dict[str, Any] = field(default_factory=dict)
    #: Report formats, overriding reporting.formats.
    formats: tuple[str, ...] = ()
    owner: str = ""
    tags: tuple[str, ...] = ()
    path: Path | None = None

    def timing(self, base: TimingSettings) -> TimingSettings:
        if not self.timing_overrides:
            return base
        merged = {
            key.removesuffix("_seconds"): getattr(base, key)
            for key in base.__slots__  # type: ignore[attr-defined]
        }
        merged.update(self.timing_overrides)
        return TimingSettings.from_dict(merged)

    def gates(self, base: GateSettings) -> GateSettings:
        if not self.gate_overrides:
            return base
        merged: dict[str, Any] = {
            "min_detection_rate": base.min_detection_rate,
            "min_visibility_rate": base.min_visibility_rate,
            "fail_on_regression": base.fail_on_regression,
            "fail_on_noise": base.fail_on_noise,
            "min_severity": base.min_severity.value,
            "fail_on_error": base.fail_on_error,
            "fail_on_latency_breach": base.fail_on_latency_breach,
            "fail_on_coverage_target": base.fail_on_coverage_target,
        }
        merged.update(self.gate_overrides)
        return GateSettings.from_dict(merged)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "backend": self.backend,
            "select": {
                "rules": list(self.select.rules),
                "platforms": list(self.select.platforms),
                "tactics": list(self.select.tactics),
                "techniques": list(self.select.techniques),
                "tags": list(self.select.tags),
                "statuses": list(self.select.statuses),
                "min_severity": self.select.min_severity.value
                if self.select.min_severity
                else None,
            },
            "exclude_rules": list(self.exclude_rules),
            "tests": list(self.tests),
            "scenarios": list(self.scenarios),
            "owner": self.owner,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: Path | None = None) -> Profile:
        name = str(data.get("name") or (path.stem if path else "")).strip()
        if not name:
            raise ConfigError(f"{path or '<inline>'}: profile has no name")
        return cls(
            name=name,
            description=str(data.get("description") or "").strip(),
            backend=str(data["backend"]) if data.get("backend") else None,
            select=Selector.from_dict(data.get("select")),
            exclude_rules=_tuple((data.get("exclude") or {}).get("rules")),
            tests=_tuple(data.get("tests")),
            scenarios=_tuple(data.get("scenarios")),
            timing_overrides=dict(data.get("timing") or {}),
            gate_overrides=dict(data.get("gates") or {}),
            formats=_tuple(data.get("formats")),
            owner=str(data.get("owner") or ""),
            tags=_tuple(data.get("tags")),
            path=path,
        )


@dataclass(slots=True)
class ProfileLibrary:
    profiles: dict[str, Profile] = field(default_factory=dict)

    def __iter__(self) -> Iterator[Profile]:
        return iter(self.profiles.values())

    def __len__(self) -> int:
        return len(self.profiles)

    def __contains__(self, name: object) -> bool:
        return str(name) in self.profiles

    def get(self, name: str) -> Profile | None:
        return self.profiles.get(name)

    def require(self, name: str) -> Profile:
        profile = self.profiles.get(name)
        if profile is None:
            known = ", ".join(sorted(self.profiles)) or "none"
            raise ConfigError(
                f"unknown profile '{name}'",
                hint=f"Available profiles: {known}",
            )
        return profile

    def names(self) -> list[str]:
        return sorted(self.profiles)


def load_profiles(directory: Path | str) -> ProfileLibrary:
    library = ProfileLibrary()
    for path in iter_yaml_files(directory, recursive=False):
        document = load_yaml(path, default={}) or {}
        if not isinstance(document, Mapping):
            raise ConfigError(f"{path}: profile must be a YAML mapping")
        profile = Profile.from_dict(document, path=path)
        library.profiles[profile.name] = profile
    return library


def default_library(settings: Settings) -> ProfileLibrary:
    return load_profiles(settings.layout.profiles)


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(v) for v in value)
    return (str(value),)
