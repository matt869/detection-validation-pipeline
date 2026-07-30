"""Rule linting.

``run_linters`` applies every registered check to every rule and returns a flat,
sorted list of findings. The CLI turns that into human output; CI turns the
error count into an exit code.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from rulekit.library import RuleLibrary
from rulekit.linters.base import Finding, Level, LintContext, Linter, filter_findings
from rulekit.linters.coverage import AttackLinter, TelemetryLinter
from rulekit.linters.logic import LogicLinter
from rulekit.linters.metadata import MetadataLinter
from rulekit.linters.validation import PortabilityLinter, ValidationLinter
from rulekit.rule import Rule

__all__ = [
    "ALL_LINTERS",
    "Finding",
    "Level",
    "LintContext",
    "Linter",
    "filter_findings",
    "lint_rule",
    "run_linters",
    "summarise",
]

#: Registration order controls report order within a rule.
ALL_LINTERS: tuple[Linter, ...] = (
    MetadataLinter(),
    LogicLinter(),
    AttackLinter(),
    TelemetryLinter(),
    ValidationLinter(),
    PortabilityLinter(),
)


def lint_rule(
    rule: Rule,
    context: LintContext,
    *,
    linters: Sequence[Linter] = ALL_LINTERS,
) -> list[Finding]:
    findings: list[Finding] = []
    for linter in linters:
        try:
            findings.extend(linter.check(rule, context))
        except Exception as exc:
            findings.append(
                Finding(
                    code="LN000",
                    level=Level.ERROR,
                    message=f"linter '{linter.category}' crashed: {type(exc).__name__}: {exc}",
                    rule_name=rule.name,
                    path=rule.path,
                )
            )
    return findings


def run_linters(
    library: RuleLibrary,
    context: LintContext | None = None,
    *,
    linters: Sequence[Linter] = ALL_LINTERS,
    only: Sequence[str] = (),
    ignore: Sequence[str] = (),
    min_level: Level = Level.INFO,
) -> list[Finding]:
    """Lint an entire library, including files that failed to parse."""
    context = context or LintContext(
        catalog=library.catalog,
        library_names=frozenset(library.rules),
        root=library.root,
    )

    findings: list[Finding] = [
        Finding(
            code="LD001",
            level=Level.ERROR,
            message=error.message,
            rule_name=error.path.stem,
            path=error.path,
            hint=error.hint,
        )
        for error in library.errors
    ]

    for rule in library:
        findings.extend(lint_rule(rule, context, linters=linters))

    for rule_id, duplicates in library.duplicate_ids().items():
        names = ", ".join(sorted(r.name for r in duplicates))
        for rule in duplicates:
            findings.append(
                Finding(
                    code="LD002",
                    level=Level.ERROR,
                    message=f"rule id {rule_id} is shared by: {names}",
                    rule_name=rule.name,
                    path=rule.path,
                    hint="Generate a fresh UUID for the copy.",
                    locator="id",
                )
            )

    return filter_findings(findings, only=only, ignore=ignore, min_level=min_level)


def summarise(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"error": 0, "warning": 0, "info": 0}
    for finding in findings:
        counts[finding.level.value] += 1
    counts["total"] = sum(counts.values())
    return counts
