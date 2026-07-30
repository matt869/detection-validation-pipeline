"""Emulation orchestration.

Takes the set of tests a plan needs, runs each one exactly once (several rules
usually share a test), and returns the resulting time windows. Tests execute
sequentially with a configurable gap: overlapping behaviours produce telemetry
that cannot be attributed to one test, which would make every latency
measurement meaningless.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from harness.core.config import Settings
from harness.core.logging import get_logger
from harness.core.models import EmulationResult
from harness.core.timeutil import TimeWindow, utcnow
from harness.emulation.catalog import TestCatalog
from harness.emulation.executors import Executor, build_executor
from harness.emulation.safety import SafetyDecision, SafetyPolicy, Target

__all__ = ["EmulationOutcome", "EmulationRunner"]

log = get_logger("emulation")


@dataclass(slots=True)
class EmulationOutcome:
    """Everything the emulation phase produced."""

    results: dict[str, EmulationResult] = field(default_factory=dict)
    decisions: dict[str, SafetyDecision] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    mode: str = "dry-run"
    target: str = "unknown"

    def anchors(self) -> dict[str, datetime]:
        """Test id -> start time, for the fixture backend to rebase onto."""
        return {
            test_id: result.started_at
            for test_id, result in self.results.items()
            if result.started_at is not None
        }

    def window(self) -> TimeWindow | None:
        """The span covering every test that ran."""
        starts = [r.started_at for r in self.results.values() if r.started_at]
        ends = [r.finished_at for r in self.results.values() if r.finished_at]
        if not starts or not ends:
            return None
        return TimeWindow(min(starts), max(ends))

    def window_for(self, test_id: str) -> TimeWindow | None:
        result = self.results.get(test_id)
        return result.window if result else None

    def executed_count(self) -> int:
        return sum(1 for r in self.results.values() if r.executed)

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "target": self.target,
            "executed": self.executed_count(),
            "planned": len(self.results),
            "skipped": dict(self.skipped),
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "safety": {k: v.to_dict() for k, v in self.decisions.items()},
        }


@dataclass(slots=True)
class EmulationRunner:
    """Executes the tests a validation plan requires."""

    settings: Settings
    catalog: TestCatalog
    policy: SafetyPolicy
    target: Target
    executor: Executor | None = None
    #: Set false to skip the inter-test pause (tests and offline replays).
    pace: bool = True

    def run(self, test_ids: Iterable[str]) -> EmulationOutcome:
        ordered = _dedupe(test_ids)
        mode = self._mode()
        executor = self.executor or build_executor(
            mode, timeout=self.settings.safety.command_timeout_seconds
        )
        outcome = EmulationOutcome(mode=mode, target=self.target.host)

        enabled, why = self.policy.execution_enabled()
        if not enabled and mode == "local":
            log.warning("execution requested but not permitted: %s", why)

        log.info(
            "emulating %d test(s) in %s mode against %s", len(ordered), mode, self.target.host
        )

        for index, test_id in enumerate(ordered):
            test = self.catalog.get(test_id)
            if test is None:
                outcome.skipped[test_id] = "no such emulation test"
                log.error("unknown emulation test '%s'", test_id)
                continue

            decision = self.policy.evaluate(test, self.target)
            outcome.decisions[test_id] = decision

            # A blocked test still gets a window in dry-run/replay: the harness
            # can then report what the telemetry looked like anyway, which is
            # often the more useful half of the answer.
            active = executor if (decision.allowed or mode != "local") else None
            if active is None:
                outcome.skipped[test_id] = decision.reason
                log.info("skipped %s: %s", test_id, decision.reason)
                continue

            result = active.run(test, self.target, decision)
            outcome.results[test_id] = result
            if result.error:
                self.policy.record_failure()
                log.error("emulation error for %s: %s", test_id, result.error)

            if self.pace and index < len(ordered) - 1:
                delay = self.settings.timing.inter_test_delay_seconds
                if delay > 0 and mode == "local":
                    time.sleep(delay)

        return outcome

    def _mode(self) -> str:
        enabled, _ = self.policy.execution_enabled()
        if enabled:
            return "local"
        # Offline runs against recorded telemetry are "replay": nothing executes,
        # but real windows are reserved so timing analysis still works.
        if self.settings.default_backend == "fixture":
            return "replay"
        return "dry-run"

    @classmethod
    def build(
        cls,
        settings: Settings,
        catalog: TestCatalog,
        *,
        execute: bool = False,
        host: str | None = None,
        backend: str | None = None,
        pace: bool = True,
    ) -> EmulationRunner:
        target = Target.local() if not host else Target(host=host, platform=Target.local().platform)
        policy = SafetyPolicy(settings=settings.safety, execution_requested=execute)
        runner = cls(
            settings=settings,
            catalog=catalog,
            policy=policy,
            target=target,
            pace=pace,
        )
        if backend == "fixture":
            # Force replay so recorded telemetry is anchored to real windows.
            runner.executor = build_executor("replay")
        return runner


def _dedupe(values: Iterable[str]) -> Sequence[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(str(value), None)
    return list(seen)


def baseline_anchor(settings: Settings, *, now: datetime | None = None) -> datetime:
    """Start of the quiet window sampled before emulation.

    Noise is measured over a period that must not overlap the emulation, or the
    behaviour under test would be counted as baseline noise.
    """
    reference = now or utcnow()
    return reference - _seconds(settings.timing.baseline_window_seconds)


def _seconds(value: float):
    from datetime import timedelta

    return timedelta(seconds=value)
