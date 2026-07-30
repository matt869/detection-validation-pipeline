"""Emulation test definitions.

A test says what behaviour to produce, how to undo it, and what telemetry it
should generate. Tests live in ``fixtures/emulation/*.yml`` so they are
reviewable content, not code.

Two deliberate choices about what ships in this repository:

* **No offensive payloads.** Tests that would need real credential-dumping or
  real destruction are declared ``executor: manual`` with a reference to the
  public technique documentation. The harness plans, times, and scores them,
  but never executes them - an operator runs them under their own authority.
* **Safe simulations where they are faithful.** Where a benign command produces
  telemetry of the same shape (creating and deleting a scheduled task, writing
  and removing a Run key), the test carries that command and is marked
  ``safe_mode: true``. These are the ones CI can actually execute in a lab.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.core.errors import ConfigError
from harness.core.timeutil import parse_duration
from harness.core.yamlio import iter_yaml_files, load_yaml

__all__ = ["EmulationTest", "TestCatalog"]

#: Executors the harness understands. `manual` is never run automatically.
EXECUTORS = ("manual", "powershell", "cmd", "bash", "sh", "python")

_PLATFORM_EXECUTORS = {
    "windows": {"powershell", "cmd", "python", "manual"},
    "linux": {"bash", "sh", "python", "manual"},
    "macos": {"bash", "sh", "python", "manual"},
    "aws": {"manual", "python", "bash", "sh"},
    "any": set(EXECUTORS),
}


@dataclass(frozen=True, slots=True)
class EmulationTest:
    """One emulated behaviour."""

    id: str
    name: str
    technique: str
    platform: str
    description: str = ""
    executor: str = "manual"
    command: str = ""
    cleanup: str = ""
    #: True when ``command`` is a benign stand-in rather than the real technique.
    safe_mode: bool = True
    #: True when the behaviour itself causes damage. Requires explicit opt-in.
    destructive: bool = False
    #: Rights the test needs. Recorded, not enforced.
    privileges: str = "user"
    prerequisites: tuple[str, ...] = ()
    #: Telemetry source ids the behaviour should produce.
    expected_telemetry: tuple[str, ...] = ()
    #: How long the behaviour takes, used to size the search window in dry runs.
    duration_seconds: float = 5.0
    timeout_seconds: float = 60.0
    references: tuple[str, ...] = ()
    #: Pointer to an equivalent public test, e.g. an Atomic Red Team GUID.
    atomic_ref: str = ""
    notes: str = ""
    path: Path | None = None

    @property
    def requires_operator(self) -> bool:
        return self.executor == "manual"

    @property
    def has_cleanup(self) -> bool:
        return bool(self.cleanup.strip())

    def supported_on(self, platform: str) -> bool:
        allowed = _PLATFORM_EXECUTORS.get(self.platform.lower(), _PLATFORM_EXECUTORS["any"])
        if self.executor not in allowed:
            return False
        return self.platform.lower() in (platform.lower(), "any")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "technique": self.technique,
            "platform": self.platform,
            "description": self.description,
            "executor": self.executor,
            "safe_mode": self.safe_mode,
            "destructive": self.destructive,
            "privileges": self.privileges,
            "prerequisites": list(self.prerequisites),
            "expected_telemetry": list(self.expected_telemetry),
            "duration_seconds": self.duration_seconds,
            "timeout_seconds": self.timeout_seconds,
            "references": list(self.references),
            "atomic_ref": self.atomic_ref,
            "has_cleanup": self.has_cleanup,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: Path | None = None) -> EmulationTest:
        context = str(path or data.get("id") or "<inline>")
        for key in ("id", "technique", "platform"):
            if not data.get(key):
                raise ConfigError(f"{context}: emulation test is missing '{key}'")

        executor = str(data.get("executor", "manual")).lower()
        if executor not in EXECUTORS:
            raise ConfigError(
                f"{context}: unknown executor '{executor}' (allowed: {', '.join(EXECUTORS)})"
            )

        command = str(data.get("command") or "").strip()
        if executor != "manual" and not command:
            raise ConfigError(
                f"{context}: executor '{executor}' requires a 'command'",
                hint="Use executor: manual for tests an operator must run themselves.",
            )

        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or data["id"]),
            technique=str(data["technique"]).upper(),
            platform=str(data["platform"]).lower(),
            description=str(data.get("description") or "").strip(),
            executor=executor,
            command=command,
            cleanup=str(data.get("cleanup") or "").strip(),
            safe_mode=bool(data.get("safe_mode", True)),
            destructive=bool(data.get("destructive", False)),
            privileges=str(data.get("privileges") or "user"),
            prerequisites=tuple(str(p) for p in (data.get("prerequisites") or [])),
            expected_telemetry=tuple(str(t) for t in (data.get("expected_telemetry") or [])),
            duration_seconds=parse_duration(data.get("duration"), default=5.0),
            timeout_seconds=parse_duration(data.get("timeout"), default=60.0),
            references=tuple(str(r) for r in (data.get("references") or [])),
            atomic_ref=str(data.get("atomic_ref") or ""),
            notes=str(data.get("notes") or "").strip(),
            path=path,
        )


@dataclass(slots=True)
class TestCatalog:
    """All known emulation tests, keyed by id."""

    tests: dict[str, EmulationTest] = field(default_factory=dict)
    path: Path | None = None

    def __iter__(self) -> Iterator[EmulationTest]:
        return iter(self.tests.values())

    def __len__(self) -> int:
        return len(self.tests)

    def __contains__(self, test_id: object) -> bool:
        return str(test_id) in self.tests

    def get(self, test_id: str) -> EmulationTest | None:
        return self.tests.get(test_id)

    def require(self, test_id: str) -> EmulationTest:
        test = self.tests.get(test_id)
        if test is None:
            raise ConfigError(
                f"unknown emulation test '{test_id}'",
                hint="Tests are defined in fixtures/emulation/*.yml; "
                "list them with `dvp tests list`.",
            )
        return test

    def ids(self) -> frozenset[str]:
        return frozenset(self.tests)

    def for_technique(self, technique: str) -> list[EmulationTest]:
        technique = technique.upper()
        return [
            t
            for t in self.tests.values()
            if t.technique == technique or t.technique.startswith(f"{technique}.")
        ]

    def for_platform(self, platform: str) -> list[EmulationTest]:
        return [t for t in self.tests.values() if t.platform in (platform.lower(), "any")]

    @classmethod
    def load(cls, directory: Path | str) -> TestCatalog:
        """Load every test file under ``directory``.

        Each file may hold a single test or a ``tests:`` list, so related
        behaviours can live together.
        """
        directory = Path(directory)
        catalog = cls(path=directory)
        if not directory.exists():
            return catalog

        for path in iter_yaml_files(directory):
            document = load_yaml(path, default={}) or {}
            entries = document.get("tests") if isinstance(document, dict) else None
            if entries is None:
                entries = [document]
            if not isinstance(entries, list):
                raise ConfigError(f"{path}: 'tests' must be a list")

            for entry in entries:
                if not isinstance(entry, dict):
                    raise ConfigError(f"{path}: each test must be a mapping")
                test = EmulationTest.from_dict(entry, path=path)
                if test.id in catalog.tests:
                    raise ConfigError(
                        f"{path}: duplicate emulation test id '{test.id}' "
                        f"(already defined in {catalog.tests[test.id].path})"
                    )
                catalog.tests[test.id] = test

        return catalog

    @classmethod
    def empty(cls) -> TestCatalog:
        return cls()
