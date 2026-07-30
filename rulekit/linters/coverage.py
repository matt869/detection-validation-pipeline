"""ATT&CK mapping and telemetry-source checks.

Together these decide whether a rule can participate in coverage reporting at
all. A rule with no technique mapping is invisible on the heat map; a rule with
no telemetry declaration cannot tell a detection gap from a visibility gap, and
so produces a low-confidence result every single run.
"""

from __future__ import annotations

from collections.abc import Iterable

from harness.core.models import RuleStatus
from rulekit.linters.base import Finding, Level, LintContext, Linter
from rulekit.rule import Rule


class AttackLinter(Linter):
    category = "attack"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        techniques = [t for t in rule.technique_ids if t]

        if not techniques:
            yield self.finding(
                rule,
                "AT001",
                Level.ERROR if rule.status is RuleStatus.PRODUCTION else Level.WARNING,
                "no ATT&CK technique mapping - the rule cannot appear in coverage reports",
                hint="Add attack.techniques: [T1059.001]",
                locator="attack",
            )
            return

        for ref in rule.attack:
            if not ref.technique:
                continue
            entry = context.technique(ref.technique)
            if context.attack and entry is None:
                yield self.finding(
                    rule,
                    "AT002",
                    Level.WARNING,
                    f"technique {ref.technique} is not in mapping/mapping.yml",
                    hint="Either it is a typo, or the mapping file needs refreshing "
                    "against the current ATT&CK release.",
                    locator="attack.techniques",
                )
                continue

            if entry and entry.get("deprecated"):
                replacement = entry.get("superseded_by")
                suffix = f"; use {replacement}" if replacement else ""
                yield self.finding(
                    rule,
                    "AT004",
                    Level.WARNING,
                    f"technique {ref.technique} is deprecated in ATT&CK{suffix}",
                    locator="attack.techniques",
                )

            if not ref.tactic:
                yield self.finding(
                    rule,
                    "AT003",
                    Level.INFO,
                    f"technique {ref.technique} has no tactic - "
                    "kill-chain reporting will place it under 'unknown'",
                    locator="attack.tactics",
                )
            elif entry:
                valid = {str(t).lower() for t in entry.get("tactics", [])}
                if valid and ref.tactic.lower() not in valid:
                    yield self.finding(
                        rule,
                        "AT005",
                        Level.WARNING,
                        f"{ref.technique} is not part of tactic '{ref.tactic}' "
                        f"(expected one of: {', '.join(sorted(valid))})",
                        locator="attack.tactics",
                    )

        # Prefer sub-techniques: "T1003" alone under-describes what is detected.
        parents_only = [t for t in techniques if "." not in t]
        if parents_only and context.attack:
            for technique in parents_only:
                entry = context.attack.get(technique) or {}
                if entry.get("subtechniques"):
                    yield self.finding(
                        rule,
                        "AT006",
                        Level.INFO,
                        f"{technique} has sub-techniques; mapping to the parent "
                        "over-states coverage",
                        hint=f"Available: {', '.join(entry['subtechniques'][:4])}",
                        locator="attack.techniques",
                    )


class TelemetryLinter(Linter):
    category = "telemetry"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        if not rule.telemetry:
            yield self.finding(
                rule,
                "TM001",
                Level.ERROR if rule.status is RuleStatus.PRODUCTION else Level.WARNING,
                "no telemetry sources declared - every result will be low-confidence "
                "because a detection gap cannot be told apart from a visibility gap",
                hint="Add telemetry: [sysmon_process_creation] referencing "
                "mapping/telemetry_sources.yml.",
                locator="telemetry",
            )
            return

        if len(context.catalog) == 0:
            return  # no catalogue loaded; nothing further to verify against

        declared_fields: set[str] = set()
        for source_id in rule.telemetry:
            source = context.catalog.get(source_id)
            if source is None:
                yield self.finding(
                    rule,
                    "TM002",
                    Level.ERROR,
                    f"unknown telemetry source '{source_id}'",
                    hint="Define it in mapping/telemetry_sources.yml.",
                    locator="telemetry",
                )
                continue

            declared_fields.update(f.casefold() for f in source.fields)

            rule_platforms = {p.casefold() for p in rule.platforms} or {rule.platform.casefold()}
            if (
                source.platform.casefold() not in ("any", "")
                and rule_platforms
                and source.platform.casefold() not in rule_platforms
            ):
                yield self.finding(
                    rule,
                    "TM003",
                    Level.WARNING,
                    f"telemetry source '{source_id}' is {source.platform} but the "
                    f"rule targets {', '.join(sorted(rule_platforms))}",
                    locator="telemetry",
                )

            for dialect in context.required_dialects:
                if not source.supports(dialect):
                    yield self.finding(
                        rule,
                        "TM004",
                        Level.WARNING,
                        f"telemetry source '{source_id}' has no '{dialect}' mapping; "
                        "the rule cannot be validated on that backend",
                        locator="telemetry",
                    )

        # Only check field availability when every source declares its fields;
        # a partially-populated catalogue would produce noise, not signal.
        if declared_fields and all(
            context.catalog.get(s) and context.catalog.require(s).fields for s in rule.telemetry
        ):
            unknown = [name for name in rule.field_names if name.casefold() not in declared_fields]
            if unknown:
                yield self.finding(
                    rule,
                    "TM005",
                    Level.WARNING,
                    f"field(s) not provided by the declared telemetry: {', '.join(unknown)}",
                    hint="Either the field list in mapping/telemetry_sources.yml is "
                    "incomplete, or the rule reads a field that will always be null.",
                    locator="detection",
                )
