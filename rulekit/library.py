"""Loading and querying the detection library.

Loading is *fault-tolerant by default*: one broken rule collects an error and
the rest of the library still loads, so ``dvp rules lint`` can report every
problem in a single pass instead of one per run. Callers that need strictness
(the pipeline planner) pass ``strict=True``.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from harness.core.errors import RuleError
from harness.core.models import RuleStatus, Severity
from harness.core.yamlio import iter_yaml_files
from rulekit.rule import Rule
from rulekit.telemetry import TelemetryCatalog

__all__ = ["LoadError", "RuleLibrary", "load_library"]


@dataclass(frozen=True, slots=True)
class LoadError:
    """A rule file that could not be loaded."""

    path: Path
    message: str
    hint: str = ""

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(slots=True)
class RuleLibrary:
    """An indexed collection of detection rules."""

    rules: dict[str, Rule] = field(default_factory=dict)
    errors: list[LoadError] = field(default_factory=list)
    root: Path | None = None
    catalog: TelemetryCatalog = field(default_factory=TelemetryCatalog.empty)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules.values())

    def __len__(self) -> int:
        return len(self.rules)

    def __contains__(self, name: object) -> bool:
        return str(name) in self.rules

    def get(self, name: str) -> Rule | None:
        return self.rules.get(name)

    def require(self, name: str) -> Rule:
        rule = self.rules.get(name)
        if rule is None:
            close = _closest(name, self.rules)
            hint = f"Did you mean '{close}'?" if close else None
            raise RuleError(f"no rule named '{name}'", hint=hint)
        return rule

    # -- selection ---------------------------------------------------------

    def select(
        self,
        *,
        names: Sequence[str] | None = None,
        platforms: Sequence[str] | None = None,
        tactics: Sequence[str] | None = None,
        techniques: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        statuses: Sequence[str] | None = None,
        min_severity: Severity | None = None,
        include_inactive: bool = False,
        require_validation: bool = False,
    ) -> list[Rule]:
        """Filter the library. All supplied criteria must match (AND).

        Technique matching is hierarchical: asking for ``T1003`` also selects
        rules tagged ``T1003.001``, because a sub-technique is a kind of its
        parent and operators expect coverage queries to work that way.
        """
        selected: list[Rule] = []
        wanted_names = {n.lower() for n in names} if names else None
        wanted_platforms = {p.lower() for p in platforms} if platforms else None
        wanted_tactics = {t.lower().replace(" ", "-") for t in tactics} if tactics else None
        wanted_techniques = {t.upper() for t in techniques} if techniques else None
        wanted_tags = {t.lower() for t in tags} if tags else None
        wanted_statuses = {s.lower() for s in statuses} if statuses else None

        for rule in self.rules.values():
            if not include_inactive and not rule.is_active:
                continue
            if wanted_names and rule.name.lower() not in wanted_names:
                continue
            if wanted_statuses and rule.status.value not in wanted_statuses:
                continue
            if min_severity is not None and rule.severity < min_severity:
                continue
            if wanted_platforms and not _overlaps(
                wanted_platforms, {p.lower() for p in rule.platforms} | {rule.platform.lower()}
            ):
                continue
            if wanted_tactics and not _overlaps(wanted_tactics, set(rule.tactics)):
                continue
            if wanted_techniques and not _technique_match(wanted_techniques, rule):
                continue
            if wanted_tags and not _overlaps(wanted_tags, {t.lower() for t in rule.tags}):
                continue
            if require_validation and not rule.validation.emulation:
                continue
            selected.append(rule)

        return sorted(selected, key=lambda r: r.name)

    # -- indexes -----------------------------------------------------------

    def by_technique(self) -> dict[str, list[Rule]]:
        index: dict[str, list[Rule]] = defaultdict(list)
        for rule in self.rules.values():
            for technique in rule.technique_ids:
                if technique:
                    index[technique].append(rule)
        return dict(index)

    def by_tactic(self) -> dict[str, list[Rule]]:
        index: dict[str, list[Rule]] = defaultdict(list)
        for rule in self.rules.values():
            for tactic in rule.tactics:
                index[tactic].append(rule)
        return dict(index)

    def by_emulation(self) -> dict[str, list[Rule]]:
        """Emulation test id -> rules that claim to detect it."""
        index: dict[str, list[Rule]] = defaultdict(list)
        for rule in self.rules.values():
            for test_id in rule.validation.emulation:
                index[test_id].append(rule)
        return dict(index)

    def duplicate_ids(self) -> dict[str, list[Rule]]:
        """UUIDs shared by more than one rule - a copy/paste artefact that
        breaks correlation between the SIEM's alerts and this library."""
        index: dict[str, list[Rule]] = defaultdict(list)
        for rule in self.rules.values():
            if rule.id:
                index[rule.id].append(rule)
        return {rule_id: rules for rule_id, rules in index.items() if len(rules) > 1}

    def stats(self) -> dict[str, int]:
        return {
            "total": len(self.rules),
            "active": sum(1 for r in self.rules.values() if r.is_active),
            "production": sum(
                1 for r in self.rules.values() if r.status is RuleStatus.PRODUCTION
            ),
            "with_validation": sum(1 for r in self.rules.values() if r.validation.emulation),
            "techniques": len(self.by_technique()),
            "errors": len(self.errors),
        }


def load_library(
    directory: Path | str,
    *,
    catalog: TelemetryCatalog | None = None,
    strict: bool = False,
    root: Path | None = None,
) -> RuleLibrary:
    """Load every rule under ``directory``.

    Files and directories prefixed with ``_`` or ``.`` are skipped, so
    ``detections/_shared/`` can hold YAML anchors and templates without being
    mistaken for rules.
    """
    directory = Path(directory)
    library = RuleLibrary(root=root or directory, catalog=catalog or TelemetryCatalog.empty())
    seen_names: dict[str, Path] = {}

    for path in iter_yaml_files(directory):
        try:
            rule = Rule.from_file(path)
        except RuleError as exc:
            if strict:
                raise
            library.errors.append(LoadError(path=path, message=exc.message, hint=exc.hint or ""))
            continue
        except Exception as exc:
            if strict:
                raise RuleError(str(exc), path=str(path)) from exc
            library.errors.append(LoadError(path=path, message=f"{type(exc).__name__}: {exc}"))
            continue

        if rule.name in seen_names:
            message = (
                f"duplicate rule name '{rule.name}' (already defined in "
                f"{seen_names[rule.name]})"
            )
            if strict:
                raise RuleError(message, path=str(path))
            library.errors.append(LoadError(path=path, message=message))
            continue

        seen_names[rule.name] = path
        library.rules[rule.name] = rule

    return library


def _overlaps(wanted: set[str], have: Iterable[str]) -> bool:
    return bool(wanted & set(have))


def _technique_match(wanted: set[str], rule: Rule) -> bool:
    for technique in rule.technique_ids:
        if not technique:
            continue
        if technique in wanted:
            return True
        # Asking for the parent technique selects its sub-techniques.
        if technique.split(".", 1)[0] in wanted:
            return True
    return False


def _closest(name: str, candidates: Iterable[str]) -> str | None:
    import difflib

    matches = difflib.get_close_matches(name, list(candidates), n=1, cutoff=0.6)
    return matches[0] if matches else None
