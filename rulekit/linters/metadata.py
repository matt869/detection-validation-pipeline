"""Metadata checks - the fields that make a rule maintainable by someone else.

These look pedantic until an alert fires at 3am and the responder has no
description, no references, and no idea who owns the rule.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from harness.core.models import RuleStatus
from rulekit.linters.base import Finding, Level, LintContext, Linter
from rulekit.rule import Rule

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
)
_MAX_TITLE = 110
_MIN_DESCRIPTION = 40


class MetadataLinter(Linter):
    category = "metadata"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        yield from self._identity(rule)
        yield from self._prose(rule)
        yield from self._provenance(rule)

        if rule.unknown_keys:
            yield self.finding(
                rule,
                "MD008",
                Level.INFO,
                f"unrecognised top-level key(s): {', '.join(rule.unknown_keys)}",
                hint="Typos here are silent - the key is simply ignored.",
            )

        if rule.path and rule.path.stem != rule.name:
            yield self.finding(
                rule,
                "MD009",
                Level.INFO,
                f"rule name '{rule.name}' does not match filename '{rule.path.stem}'",
                hint="Matching them makes rules findable by grep and by path.",
            )

    def _identity(self, rule: Rule) -> Iterable[Finding]:
        if not rule.id:
            yield self.finding(
                rule,
                "MD001",
                Level.ERROR if rule.status is RuleStatus.PRODUCTION else Level.WARNING,
                "no 'id' - alerts in the SIEM cannot be traced back to this file",
                hint="Add a UUID4: python -c \"import uuid;print(uuid.uuid4())\"",
                locator="id",
            )
        elif not _UUID_RE.match(rule.id):
            yield self.finding(
                rule,
                "MD002",
                Level.WARNING,
                f"'id' is not a UUID: {rule.id!r}",
                hint="UUIDs avoid collisions when rules are shared between teams.",
                locator="id",
            )

    def _prose(self, rule: Rule) -> Iterable[Finding]:
        if len(rule.title) > _MAX_TITLE:
            yield self.finding(
                rule,
                "MD003",
                Level.WARNING,
                f"title is {len(rule.title)} characters; most alert consoles truncate at ~{_MAX_TITLE}",
                locator="title",
            )
        if rule.title.endswith("."):
            yield self.finding(
                rule, "MD003", Level.INFO, "title should not end with a full stop", locator="title"
            )

        if not rule.description:
            yield self.finding(
                rule,
                "MD004",
                Level.ERROR if rule.status is RuleStatus.PRODUCTION else Level.WARNING,
                "no 'description' - a responder has nothing to triage against",
                hint="Say what the behaviour is, why it is suspicious, and what to check first.",
                locator="description",
            )
        elif len(rule.description) < _MIN_DESCRIPTION:
            yield self.finding(
                rule,
                "MD004",
                Level.INFO,
                f"description is only {len(rule.description)} characters",
                hint="Aim for a sentence on the behaviour and a sentence on triage.",
                locator="description",
            )

        if rule.status is RuleStatus.PRODUCTION and not rule.falsepositives:
            yield self.finding(
                rule,
                "MD011",
                Level.WARNING,
                "production rule declares no known false positives",
                hint="Even 'none observed in 90 days' is useful - it records that "
                "someone looked.",
                locator="falsepositives",
            )

    def _provenance(self, rule: Rule) -> Iterable[Finding]:
        if not rule.author:
            yield self.finding(
                rule,
                "MD005",
                Level.WARNING,
                "no 'author' - nobody is accountable for this rule",
                hint="A team alias ages better than an individual's name.",
                locator="author",
            )
        if not rule.date:
            yield self.finding(
                rule, "MD006", Level.WARNING, "no 'date'", locator="date"
            )
        if rule.status is RuleStatus.PRODUCTION and not rule.references:
            yield self.finding(
                rule,
                "MD007",
                Level.WARNING,
                "production rule has no references",
                hint="Link the ATT&CK page, the research post, or the incident that "
                "motivated the rule.",
                locator="references",
            )
        if rule.status is RuleStatus.DEPRECATED and not rule.modified:
            yield self.finding(
                rule,
                "MD010",
                Level.INFO,
                "deprecated rule has no 'modified' date",
                hint="Record when it was retired so cleanup can be scheduled.",
                locator="modified",
            )
