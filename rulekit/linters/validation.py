"""Checks on the ``validation:`` block and on cross-dialect portability.

An unvalidated rule is a claim, not a control. These checks make the claim
falsifiable before the rule ships.
"""

from __future__ import annotations

from collections.abc import Iterable

from harness.core.errors import CompileError
from harness.core.models import Outcome, RuleStatus
from rulekit.compilers import get_compiler
from rulekit.linters.base import Finding, Level, LintContext, Linter
from rulekit.rule import Rule

#: Below this, a latency budget is unrealistic for any batch-indexed platform.
_MIN_SENSIBLE_LATENCY = 30.0
#: Above this, "detected" stops being operationally meaningful.
_MAX_SENSIBLE_LATENCY = 86_400.0


class ValidationLinter(Linter):
    category = "validation"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        spec = rule.validation

        if not spec.emulation:
            yield self.finding(
                rule,
                "VL001",
                Level.ERROR if rule.status is RuleStatus.PRODUCTION else Level.WARNING,
                "no emulation tests - this rule has never been proven to fire",
                hint="Add validation.emulation: [T1059.001-powershell-encoded] and "
                "define the test under fixtures/.",
                locator="validation.emulation",
            )
        elif context.known_tests:
            for test_id in spec.emulation:
                if test_id not in context.known_tests:
                    yield self.finding(
                        rule,
                        "VL002",
                        Level.ERROR,
                        f"unknown emulation test '{test_id}'",
                        hint="Test ids come from fixtures/emulation/*.yml.",
                        locator="validation.emulation",
                    )

        if spec.expect is not Outcome.DETECTED:
            level = Level.WARNING if rule.status is RuleStatus.PRODUCTION else Level.INFO
            yield self.finding(
                rule,
                "VL003",
                level,
                f"expected outcome is '{spec.expect.value}', not 'detected' - "
                "this is a documented gap, not a working control",
                hint=spec.justification or "Record an owner and a target date.",
                locator="validation.expect",
            )
            if not spec.owner:
                yield self.finding(
                    rule,
                    "VL006",
                    Level.WARNING,
                    "an accepted gap has no owner; nobody is going to close it",
                    locator="validation.owner",
                )

        if spec.max_latency_seconds < _MIN_SENSIBLE_LATENCY:
            yield self.finding(
                rule,
                "VL004",
                Level.INFO,
                f"latency budget of {spec.max_latency_seconds:.0f}s is shorter than "
                "typical ingestion lag; expect spurious breaches",
                locator="validation.max_latency",
            )
        elif spec.max_latency_seconds > _MAX_SENSIBLE_LATENCY:
            yield self.finding(
                rule,
                "VL004",
                Level.INFO,
                f"latency budget of {spec.max_latency_seconds / 3600:.0f}h is so long "
                "that a breach would never be reported",
                locator="validation.max_latency",
            )

        if not spec.enabled:
            yield self.finding(
                rule,
                "VL005",
                Level.INFO,
                "validation is disabled; the rule is planned but never executed",
                locator="validation.enabled",
            )


class PortabilityLinter(Linter):
    """Compile the rule against every required dialect.

    This is the check that catches "works in the fixture backend, throws in
    production" - a rule using a modifier the target platform cannot express.
    """

    category = "portability"

    def check(self, rule: Rule, context: LintContext) -> Iterable[Finding]:
        for dialect in context.required_dialects:
            try:
                compiler = get_compiler(dialect, context.catalog)
                compiler.compile(rule)
            except CompileError as exc:
                yield self.finding(
                    rule,
                    "PT001",
                    Level.ERROR,
                    f"does not compile for '{dialect}': {exc.message}",
                    hint=exc.hint or "",
                    locator="detection",
                )
                continue
            except Exception as exc:
                yield self.finding(
                    rule,
                    "PT002",
                    Level.ERROR,
                    f"compiler for '{dialect}' raised {type(exc).__name__}: {exc}",
                    locator="detection",
                )
                continue

            try:
                if compiler.compile_telemetry(rule) is None:
                    yield self.finding(
                        rule,
                        "PT003",
                        Level.WARNING,
                        f"no telemetry probe available for '{dialect}'; three-state "
                        "classification will fall back to low confidence",
                        hint="Add a backends." + dialect + ".scope entry to the rule's "
                        "telemetry sources.",
                        locator="telemetry",
                    )
            except CompileError as exc:
                yield self.finding(
                    rule,
                    "PT004",
                    Level.WARNING,
                    f"telemetry probe for '{dialect}' failed to compile: {exc.message}",
                    locator="telemetry",
                )
