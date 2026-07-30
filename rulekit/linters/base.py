"""Linter framework: findings, context, and the base checker class.

Every check is a small class with a stable code (``LG001``) so teams can
suppress an individual rule in CI without disabling a whole category, and so a
finding can be referenced in a code review by name.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from rulekit.rule import Rule
from rulekit.telemetry import TelemetryCatalog

__all__ = ["Finding", "Level", "LintContext", "Linter"]


class Level(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"error": 3, "warning": 2, "info": 1}[self.value]


@dataclass(frozen=True, slots=True)
class Finding:
    """One lint result."""

    code: str
    level: Level
    message: str
    rule_name: str = ""
    path: Path | None = None
    hint: str = ""
    #: Where in the rule the problem is (``detection.selection.Image``).
    locator: str = ""

    def format(self, *, root: Path | None = None) -> str:
        location = str(self.path or self.rule_name)
        if root and self.path:
            try:
                location = str(self.path.relative_to(root)).replace("\\", "/")
            except ValueError:
                pass
        suffix = f" [{self.locator}]" if self.locator else ""
        line = f"{location}: {self.level.value}: {self.code}{suffix}: {self.message}"
        return f"{line}\n    hint: {self.hint}" if self.hint else line

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "level": self.level.value,
            "message": self.message,
            "rule": self.rule_name,
            "path": str(self.path) if self.path else None,
            "hint": self.hint,
            "locator": self.locator,
        }


@dataclass(slots=True)
class LintContext:
    """Everything the checks may consult beyond the rule itself.

    Supplying these as data (rather than importing the harness) keeps
    ``rulekit`` free of runtime dependencies, so linting works in a pre-commit
    hook with no SIEM, no database, and no emulation library present.
    """

    catalog: TelemetryCatalog = field(default_factory=TelemetryCatalog.empty)
    #: Emulation test ids that actually exist.
    known_tests: frozenset[str] = frozenset()
    #: technique id -> metadata from mapping/mapping.yml.
    attack: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: Dialects a rule must compile to before it can ship.
    required_dialects: tuple[str, ...] = ()
    #: Rule names already present in the library, for cross-references.
    library_names: frozenset[str] = frozenset()
    root: Path | None = None

    def technique(self, technique_id: str) -> Mapping[str, Any] | None:
        entry = self.attack.get(technique_id)
        if entry is None and "." in technique_id:
            return self.attack.get(technique_id.split(".", 1)[0])
        return entry


class Linter:
    """Base class for a group of related checks."""

    #: Short name used in ``--only`` / ``--ignore`` selectors.
    category: str = "generic"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        raise NotImplementedError

    # -- helpers for subclasses

    def finding(
        self,
        rule: Rule,
        code: str,
        level: Level,
        message: str,
        *,
        hint: str = "",
        locator: str = "",
    ) -> Finding:
        return Finding(
            code=code,
            level=level,
            message=message,
            rule_name=rule.name,
            path=rule.path,
            hint=hint,
            locator=locator,
        )


def filter_findings(
    findings: Iterable[Finding],
    *,
    only: Sequence[str] = (),
    ignore: Sequence[str] = (),
    min_level: Level = Level.INFO,
) -> list[Finding]:
    """Apply ``--only`` / ``--ignore`` code selectors and a level floor.

    Selectors match either a full code (``LG001``) or a code prefix (``LG``),
    so a team can silence a whole category or one specific check.
    """
    only_upper = tuple(s.upper() for s in only)
    ignore_upper = tuple(s.upper() for s in ignore)

    def matches(code: str, selectors: tuple[str, ...]) -> bool:
        return any(code == s or code.startswith(s) for s in selectors)

    result = []
    for finding in findings:
        if finding.level.rank < min_level.rank:
            continue
        if only_upper and not matches(finding.code, only_upper):
            continue
        if ignore_upper and matches(finding.code, ignore_upper):
            continue
        result.append(finding)
    return sorted(result, key=lambda f: (-f.level.rank, f.rule_name, f.code))


def iter_selections(rule: Rule) -> Iterator[tuple[str, Any]]:
    """Yield ``(name, selection)`` for every selection, skipping ``condition``."""
    for name, selection in rule.detection.items():
        if name != "condition":
            yield name, selection
