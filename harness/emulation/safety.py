"""The safety policy.

Everything that could touch a real machine passes through here first. The
design assumption is that the pipeline will one day be run by someone who has
not read the documentation, against an inventory they did not build, from a CI
job nobody is watching. Under that assumption:

* **Default deny.** With no configuration at all, nothing executes. The
  pipeline still plans, still queries, still reports - it simply does not run
  commands.
* **Authorisation is a recorded human act.** ``authorized: true`` alone is not
  enough; an ``authorization_reference`` (a change ticket, a rules-of-engagement
  document) is stored with every run so the record can be audited later.
* **Allowlists, not denylists, for targets.** An empty ``host_allowlist`` means
  no host is permitted, not every host.
* **Destruction is out of scope.** Impact techniques are denied by default and
  cannot be enabled by a profile - only by a deliberate edit to settings.

Refusals are never retried and never downgraded. A blocked test is reported as
``SKIPPED`` with the reason attached, so the report shows plainly that coverage
was not measured rather than implying it was measured and passed.
"""

from __future__ import annotations

import fnmatch
import platform as platform_module
from collections.abc import Iterable
from dataclasses import dataclass, field

from harness.core.config import SafetySettings
from harness.core.logging import get_logger
from harness.emulation.catalog import EmulationTest

__all__ = ["SafetyDecision", "SafetyPolicy", "Target"]

log = get_logger("safety")

#: Substrings in a hostname that suggest a production asset.
_PRODUCTION_MARKERS = ("prod", "prd", "live", "dc0", "dc1", "domaincontroller")
#: Substrings that mark a host as an intentional lab target.
_LAB_MARKERS = ("lab", "test", "dev", "range", "sandbox", "purple", "staging")


@dataclass(frozen=True, slots=True)
class Target:
    """Where a test would run."""

    host: str
    platform: str = ""
    tags: tuple[str, ...] = ()

    @classmethod
    def local(cls) -> Target:
        system = platform_module.system().lower()
        mapping = {"windows": "windows", "linux": "linux", "darwin": "macos"}
        return cls(
            host=platform_module.node() or "localhost",
            platform=mapping.get(system, system or "unknown"),
        )

    @property
    def looks_like_lab(self) -> bool:
        haystack = f"{self.host} {' '.join(self.tags)}".lower()
        return any(marker in haystack for marker in _LAB_MARKERS)

    @property
    def looks_like_production(self) -> bool:
        haystack = f"{self.host} {' '.join(self.tags)}".lower()
        return any(marker in haystack for marker in _PRODUCTION_MARKERS)


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """The outcome of evaluating one test against the policy."""

    allowed: bool
    reason: str = ""
    #: Every check that ran, for the audit trail: ``(name, passed, detail)``.
    checks: tuple[tuple[str, bool, str], ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def blocked_by(self) -> str:
        return next((name for name, passed, _ in self.checks if not passed), "")

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "checks": [
                {"name": n, "passed": p, "detail": d} for n, p, d in self.checks
            ],
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class SafetyPolicy:
    """Evaluates whether a test may execute against a target."""

    settings: SafetySettings
    #: Set by the CLI's --execute flag. False means "plan but do not run".
    execution_requested: bool = False
    #: Populated as tests fail, to enforce ``max_failures``.
    failures: int = 0
    _audit: list[tuple[str, SafetyDecision]] = field(default_factory=list, repr=False)

    # -- top-level gate ----------------------------------------------------

    def execution_enabled(self) -> tuple[bool, str]:
        """Whether *any* execution is permitted in this invocation."""
        if not self.execution_requested:
            return False, "dry run: --execute was not given"
        if not self.settings.authorized:
            return False, (
                "safety.authorized is false; no command will be executed. "
                "This is the default and it is deliberate"
            )
        if not self.settings.authorization_reference.strip():
            return False, (
                "safety.authorized is true but safety.authorization_reference is empty; "
                "an authorisation must be traceable to a ticket or engagement document"
            )
        return True, "authorised"

    # -- per-test evaluation ------------------------------------------------

    def evaluate(self, test: EmulationTest, target: Target) -> SafetyDecision:
        """Run every check against one test. Order is significant: the first
        failure is what gets reported as ``blocked_by``."""
        checks: list[tuple[str, bool, str]] = []
        warnings: list[str] = []

        enabled, why = self.execution_enabled()
        checks.append(("execution_enabled", enabled, why))

        allowed_host = self._host_allowed(target.host)
        checks.append(
            (
                "host_allowlist",
                allowed_host,
                f"{target.host} vs {list(self.settings.host_allowlist) or 'empty (deny all)'}",
            )
        )

        lab_ok = (not self.settings.require_lab_tag) or target.looks_like_lab
        checks.append(
            ("lab_tag", lab_ok, f"host '{target.host}' does not look like a lab system")
        )
        if target.looks_like_production:
            warnings.append(
                f"target '{target.host}' matches a production naming pattern"
            )

        not_denied = not self._technique_matches(test.technique, self.settings.technique_denylist)
        checks.append(
            ("technique_denylist", not_denied, f"{test.technique} is on the denylist")
        )

        in_allowlist = not self.settings.technique_allowlist or self._technique_matches(
            test.technique, self.settings.technique_allowlist
        )
        checks.append(
            ("technique_allowlist", in_allowlist, f"{test.technique} is not on the allowlist")
        )

        destructive_ok = (not test.destructive) or self.settings.allow_destructive
        checks.append(
            (
                "destructive",
                destructive_ok,
                "test is marked destructive and safety.allow_destructive is false",
            )
        )

        cleanup_ok = (not self.settings.require_cleanup) or test.has_cleanup
        checks.append(
            ("cleanup_defined", cleanup_ok, "test defines no cleanup block")
        )

        automatable = not test.requires_operator
        checks.append(
            (
                "executor",
                automatable,
                "executor is 'manual' - this test is run by an operator, not the harness",
            )
        )

        platform_ok = test.supported_on(target.platform) if target.platform else True
        checks.append(
            (
                "platform",
                platform_ok,
                f"test targets {test.platform}, host is {target.platform or 'unknown'}",
            )
        )

        under_budget = self.failures < self.settings.max_failures
        checks.append(
            (
                "failure_budget",
                under_budget,
                f"{self.failures} failures already, budget is {self.settings.max_failures}",
            )
        )

        if not test.safe_mode:
            warnings.append(
                "test runs the real technique rather than a benign simulation"
            )

        failed = [(name, detail) for name, passed, detail in checks if not passed]
        decision = SafetyDecision(
            allowed=not failed,
            reason=failed[0][1] if failed else "all safety checks passed",
            checks=tuple(checks),
            warnings=tuple(warnings),
        )
        self._audit.append((test.id, decision))
        if not decision.allowed:
            # In a dry run or replay nothing was going to execute anyway, so a
            # refusal is expected and belongs at debug. A refusal during a real
            # execution run is the operator's answer to "why did nothing
            # happen?" and belongs at info.
            level = log.info if self.execution_requested else log.debug
            level("blocked %s: %s", test.id, decision.reason)
        return decision

    def record_failure(self) -> None:
        self.failures += 1

    def audit_trail(self) -> list[dict[str, object]]:
        return [{"test": test_id, **decision.to_dict()} for test_id, decision in self._audit]

    # -- internals ---------------------------------------------------------

    def _host_allowed(self, host: str) -> bool:
        """Glob match against the allowlist. Empty allowlist denies everything."""
        patterns = self.settings.host_allowlist
        if not patterns:
            return False
        lowered = host.lower()
        return any(
            fnmatch.fnmatch(lowered, pattern.lower())
            or fnmatch.fnmatch(lowered.split(".", 1)[0], pattern.lower())
            for pattern in patterns
        )

    @staticmethod
    def _technique_matches(technique: str, patterns: Iterable[str]) -> bool:
        """A parent technique on a list also matches its sub-techniques."""
        technique = technique.upper()
        parent = technique.split(".", 1)[0]
        for pattern in patterns:
            candidate = str(pattern).upper()
            if candidate in (technique, parent):
                return True
            if fnmatch.fnmatch(technique, candidate):
                return True
        return False
