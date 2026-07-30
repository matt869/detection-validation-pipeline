"""Quality gates: turning a run into a CI pass/fail.

A gate is only useful if it fails for the right reason, so each one reports the
specific cases responsible rather than just a threshold breach. Severity
filtering is applied consistently: a gate never fails a build over an
informational rule unless the operator asked for that.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from harness.analysis.baseline import NoiseFinding
from harness.analysis.coverage import CoverageReport
from harness.analysis.diff import RunDiff
from harness.core.config import GateSettings
from harness.core.models import CaseStatus, Outcome, RunRecord, Severity

__all__ = ["GateOutcome", "GateResult", "evaluate_gates"]


@dataclass(frozen=True, slots=True)
class GateResult:
    name: str
    passed: bool
    message: str
    #: Case keys or technique ids responsible for a failure.
    offenders: tuple[str, ...] = ()
    #: When false, the gate did not apply (not configured, no data).
    applicable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "applicable": self.applicable,
            "message": self.message,
            "offenders": list(self.offenders),
        }


@dataclass(slots=True)
class GateOutcome:
    results: list[GateResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results if r.applicable)

    def failures(self) -> list[GateResult]:
        return [r for r in self.results if r.applicable and not r.passed]

    def summary(self) -> str:
        failures = self.failures()
        if not failures:
            applicable = sum(1 for r in self.results if r.applicable)
            return f"all {applicable} gate(s) passed"
        return "; ".join(f"{r.name}: {r.message}" for r in failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "results": [r.to_dict() for r in self.results],
        }


def evaluate_gates(
    run: RunRecord,
    settings: GateSettings,
    *,
    diff: RunDiff | None = None,
    coverage: CoverageReport | None = None,
    noise: Iterable[NoiseFinding] = (),
) -> GateOutcome:
    """Apply every configured gate to a completed run."""
    outcome = GateOutcome()
    summary = run.summarise()
    threshold = settings.min_severity

    # -- errors ------------------------------------------------------------
    errored = [r for r in run.results if r.status is CaseStatus.ERROR]
    outcome.results.append(
        GateResult(
            name="no-errors",
            applicable=settings.fail_on_error,
            passed=not errored,
            message=(
                f"{len(errored)} case(s) errored - the run did not measure what it claims to"
                if errored
                else "no cases errored"
            ),
            offenders=tuple(_key(r) for r in errored[:20]),
        )
    )

    # -- expectation failures ----------------------------------------------
    failed = [
        r
        for r in run.results
        if r.status is CaseStatus.FAIL and r.case.severity >= threshold
    ]
    outcome.results.append(
        GateResult(
            name="expectations-met",
            passed=not failed,
            message=(
                f"{len(failed)} case(s) at or above {threshold.value} did not meet "
                "their documented expectation"
                if failed
                else "every case matched its documented expectation"
            ),
            offenders=tuple(_key(r) for r in failed[:20]),
        )
    )

    # -- regressions --------------------------------------------------------
    regressions = [
        d
        for d in (diff.regressions if diff else [])
        if Severity.parse(d.severity, default=Severity.MEDIUM) >= threshold
    ]
    outcome.results.append(
        GateResult(
            name="no-regressions",
            applicable=settings.fail_on_regression and diff is not None,
            passed=not regressions,
            message=(
                f"{len(regressions)} detection(s) regressed since "
                f"{diff.baseline_run_id if diff else 'the previous run'}"
                if regressions
                else "no regressions against the previous run"
            ),
            offenders=tuple(d.describe() for d in regressions[:20]),
        )
    )

    # -- detection rate -----------------------------------------------------
    outcome.results.append(
        _rate_gate(
            name="detection-rate",
            actual=summary.detection_rate,
            target=settings.min_detection_rate,
            label="detection rate",
            offenders=tuple(
                _key(r) for r in run.results if r.outcome is Outcome.VISIBLE
            )[:20],
        )
    )

    # -- visibility rate ----------------------------------------------------
    outcome.results.append(
        _rate_gate(
            name="visibility-rate",
            actual=summary.visibility_rate,
            target=settings.min_visibility_rate,
            label="telemetry visibility",
            offenders=tuple(_key(r) for r in run.results if r.outcome is Outcome.BLIND)[:20],
        )
    )

    # -- noise --------------------------------------------------------------
    noise_findings = [
        n for n in noise if Severity.parse(n.severity, default=Severity.MEDIUM) >= threshold
    ]
    outcome.results.append(
        GateResult(
            name="noise-budget",
            applicable=settings.fail_on_noise,
            passed=not noise_findings,
            message=(
                f"{len(noise_findings)} rule(s) exceeded their accepted baseline noise"
                if noise_findings
                else "no rule exceeded its accepted baseline noise"
            ),
            offenders=tuple(n.describe() for n in noise_findings[:20]),
        )
    )

    # -- latency ------------------------------------------------------------
    breached = [
        r for r in run.results if r.breached_latency and r.case.severity >= threshold
    ]
    outcome.results.append(
        GateResult(
            name="latency-budget",
            applicable=settings.fail_on_latency_breach,
            passed=not breached,
            message=(
                f"{len(breached)} detection(s) exceeded their latency budget"
                if breached
                else "every detection met its latency budget"
            ),
            offenders=tuple(
                f"{_key(r)} ({r.latency_seconds:.0f}s > {r.case.max_latency_seconds:.0f}s)"
                for r in breached[:20]
            ),
        )
    )

    # -- coverage targets ----------------------------------------------------
    failing = coverage.failing_tactics() if coverage else []
    critical = [t for t in failing if t.priority in ("critical", "high")]
    outcome.results.append(
        GateResult(
            name="coverage-targets",
            applicable=(
                settings.fail_on_coverage_target
                and coverage is not None
                and bool(coverage.tactics)
            ),
            passed=not critical,
            message=(
                f"{len(critical)} high-priority tactic(s) below target"
                if critical
                else "all high-priority tactics meet their coverage target"
            ),
            offenders=tuple(
                f"{t.tactic}: detection {t.detection_rate:.0%} "
                f"(target {t.target_detected:.0%}), visibility {t.visibility_rate:.0%} "
                f"(target {t.target_visible:.0%})"
                for t in critical[:20]
            ),
        )
    )

    return outcome


def _rate_gate(
    *,
    name: str,
    actual: float,
    target: float,
    label: str,
    offenders: tuple[str, ...],
) -> GateResult:
    applicable = target > 0
    passed = (not applicable) or actual >= target
    return GateResult(
        name=name,
        applicable=applicable,
        passed=passed,
        message=(
            f"{label} {actual:.0%} is below the {target:.0%} target"
            if applicable and not passed
            else f"{label} {actual:.0%} meets the {target:.0%} target"
        ),
        offenders=() if passed else offenders,
    )


def _key(result: Any) -> str:
    return f"{result.case.rule_name}/{result.case.emulation_id}"
