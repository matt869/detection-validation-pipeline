"""The validation pipeline.

Seven stages, in order, each producing something the next one consumes:

    plan -> baseline -> emulate -> settle -> collect -> classify -> score

``plan`` is separable on purpose (``dvp run --plan-only``): an operator should
be able to see exactly which behaviours would be produced on which host before
anything executes.

``baseline`` runs *before* emulation, over a window in which nothing was
emulated, so the behaviour under test cannot be mistaken for background noise.

``settle`` exists because querying too early is the most common way to
manufacture a false visibility gap. Against a live backend the pipeline waits
for the configured ingestion lag and then polls; against recorded fixtures it
skips the wait entirely, which is why an offline run takes seconds.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from harness.analysis.baseline import NoiseFinding, assess_noise
from harness.analysis.baseline import ProfileLibrary as BaselineLibrary
from harness.analysis.classify import Observation, classify
from harness.analysis.coverage import (
    AttackReference,
    CoverageReport,
    CoverageTargets,
    build_coverage,
)
from harness.analysis.diff import RunDiff, diff_runs
from harness.analysis.gates import GateOutcome, evaluate_gates
from harness.backends import BASELINE_TEST_ID, Backend, FixtureBackend, build_backend
from harness.backends.base import QueryResult
from harness.core.config import Settings, load_settings
from harness.core.errors import CompileError, ConfigError, DvpError
from harness.core.ids import new_case_id, new_run_id
from harness.core.logging import get_logger
from harness.core.models import (
    CaseResult,
    RunRecord,
    ValidationCase,
)
from harness.core.timeutil import TimeWindow, to_utc, utcnow
from harness.emulation import EmulationOutcome, EmulationRunner, TestCatalog
from harness.profiles import Profile, ProfileLibrary, load_profiles
from harness.store import Store
from rulekit.compilers import CompiledQuery, QueryCompiler, get_compiler
from rulekit.library import RuleLibrary, load_library
from rulekit.rule import Rule
from rulekit.telemetry import TelemetryCatalog

__all__ = ["Pipeline", "PipelineResult", "Workspace"]

log = get_logger("pipeline")


@dataclass(slots=True)
class Workspace:
    """Everything loaded from disk once, then reused across commands."""

    settings: Settings
    telemetry: TelemetryCatalog
    rules: RuleLibrary
    tests: TestCatalog
    profiles: ProfileLibrary
    attack: AttackReference
    targets: CoverageTargets
    baselines: BaselineLibrary

    @classmethod
    def load(cls, root: Path | None = None, *, settings: Settings | None = None) -> Workspace:
        settings = settings or load_settings(root=root)
        layout = settings.layout
        telemetry = TelemetryCatalog.load(layout.mapping / "telemetry_sources.yml")
        return cls(
            settings=settings,
            telemetry=telemetry,
            rules=load_library(layout.detections, catalog=telemetry, root=layout.root),
            tests=TestCatalog.load(layout.fixtures / "emulation"),
            profiles=load_profiles(layout.profiles),
            attack=AttackReference.load(layout.mapping / "mapping.yml"),
            targets=CoverageTargets.load(layout.mapping / "coverage_targets.yml"),
            baselines=BaselineLibrary.load(layout.baseline_profiles),
        )

    def store(self) -> Store:
        return Store(
            self.settings.database_path,
            migrations_dir=self.settings.layout.migrations,
        )


@dataclass(slots=True)
class PipelineResult:
    """Everything one invocation produced."""

    run: RunRecord
    coverage: CoverageReport | None = None
    gates: GateOutcome | None = None
    diff: RunDiff | None = None
    noise: list[NoiseFinding] = field(default_factory=list)
    emulation: EmulationOutcome | None = None
    plan_only: bool = False

    @property
    def passed(self) -> bool:
        return self.gates is None or self.gates.passed


class Pipeline:
    """Runs a validation profile end to end."""

    def __init__(
        self,
        workspace: Workspace,
        *,
        on_case: Callable[[CaseResult], None] | None = None,
    ) -> None:
        self.workspace = workspace
        self.settings = workspace.settings
        self.on_case = on_case

    # -- stage 1: plan -----------------------------------------------------

    def plan(self, profile: Profile, *, run_id: str | None = None) -> list[ValidationCase]:
        """Resolve a profile into concrete validation cases.

        A rule with three emulation tests becomes three cases: each variant of a
        technique is proven separately, because a rule that catches one and
        misses another is only half a control.
        """
        run_id = run_id or "plan"
        backend_name = profile.backend or self.settings.default_backend

        selected = self.workspace.rules.select(
            names=profile.select.rules or None,
            platforms=profile.select.platforms or None,
            tactics=profile.select.tactics or None,
            techniques=profile.select.techniques or None,
            tags=profile.select.tags or None,
            statuses=profile.select.statuses or None,
            min_severity=profile.select.min_severity,
            include_inactive=profile.select.include_inactive,
        )
        excluded = {name.lower() for name in profile.exclude_rules}
        selected = [rule for rule in selected if rule.name.lower() not in excluded]

        wanted_tests = set(profile.tests)
        cases: list[ValidationCase] = []

        for rule in selected:
            if not rule.validation.emulation:
                log.debug("skipping %s: no emulation tests declared", rule.name)
                continue
            for test_id in rule.validation.emulation:
                if wanted_tests and test_id not in wanted_tests:
                    continue
                cases.append(self._build_case(run_id, rule, test_id, backend_name))

        cases.sort(key=lambda c: (c.rule_name, c.emulation_id))
        log.info(
            "planned %d case(s) from %d rule(s) for profile '%s'",
            len(cases),
            len(selected),
            profile.name,
        )
        return cases

    def _build_case(
        self, run_id: str, rule: Rule, test_id: str, backend: str
    ) -> ValidationCase:
        skip: str | None = None
        if not rule.validation.enabled:
            skip = "validation is disabled for this rule"
        elif self.workspace.tests and test_id not in self.workspace.tests:
            skip = f"emulation test '{test_id}' is not defined"

        return ValidationCase(
            case_id=new_case_id(run_id, rule.name, test_id),
            rule_name=rule.name,
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            attack=list(rule.attack),
            platform=rule.platform,
            emulation_id=test_id,
            backend=backend,
            expected=rule.validation.expect,
            telemetry=list(rule.telemetry),
            max_latency_seconds=rule.validation.max_latency_seconds,
            tags=list(rule.tags),
            skip_reason=skip,
        )

    # -- full run ----------------------------------------------------------

    def run(
        self,
        profile: Profile,
        *,
        execute: bool = False,
        backend_name: str | None = None,
        host: str | None = None,
        plan_only: bool = False,
        compare: bool = True,
        operator: str = "unknown",
        git_ref: str | None = None,
    ) -> PipelineResult:
        settings = self.settings
        timing = profile.timing(settings.timing)
        gates_config = profile.gates(settings.gates)
        backend_name = backend_name or profile.backend or settings.default_backend

        run_id = new_run_id()
        started = utcnow()
        cases = self.plan(profile, run_id=run_id)

        record = RunRecord(
            run_id=run_id,
            profile=profile.name,
            backend=backend_name,
            started_at=started,
            operator=operator,
            git_ref=git_ref,
            metadata={
                "rules_selected": len({c.rule_name for c in cases}),
                "tests_planned": len({c.emulation_id for c in cases}),
                "profile_description": profile.description,
                "labels": dict(settings.labels),
            },
        )

        if plan_only:
            record.finished_at = utcnow()
            record.mode = "plan"
            return PipelineResult(run=record, plan_only=True)

        if not cases:
            record.finished_at = utcnow()
            record.errors.append(
                f"profile '{profile.name}' selected no validation cases - "
                "check its select: block against `dvp rules list`"
            )
            return PipelineResult(run=record)

        backend = build_backend(settings, backend_name, scenarios=profile.scenarios or None)
        try:
            return self._execute(
                profile=profile,
                record=record,
                cases=cases,
                backend=backend,
                timing=timing,
                gates_config=gates_config,
                execute=execute,
                host=host,
                compare=compare,
            )
        finally:
            backend.close()

    # -- stages 2-7 --------------------------------------------------------

    def _execute(
        self,
        *,
        profile: Profile,
        record: RunRecord,
        cases: Sequence[ValidationCase],
        backend: Backend,
        timing,
        gates_config,
        execute: bool,
        host: str | None,
        compare: bool,
    ) -> PipelineResult:
        settings = self.settings
        compiler = self._compiler(backend)

        # -- stage 2: baseline window (before anything is emulated) --------
        baseline_end = utcnow()
        baseline_window = TimeWindow(
            start=baseline_end - timedelta(seconds=timing.baseline_window_seconds),
            end=baseline_end,
        )

        # -- stage 3: emulate ----------------------------------------------
        runner = EmulationRunner.build(
            settings,
            self.workspace.tests,
            execute=execute,
            host=host,
            backend=backend.dialect,
            pace=execute,
        )
        test_ids = [c.emulation_id for c in cases if not c.skip_reason]
        emulation = runner.run(test_ids)
        record.mode = emulation.mode
        record.metadata["emulation"] = {
            "mode": emulation.mode,
            "target": emulation.target,
            "executed": emulation.executed_count(),
            "skipped": emulation.skipped,
        }

        if isinstance(backend, FixtureBackend):
            backend.set_anchors(emulation.anchors(), baseline=baseline_window.start)

        # -- stage 4: settle -------------------------------------------------
        live = emulation.mode == "local" and not isinstance(backend, FixtureBackend)
        if live and timing.ingest_lag_seconds > 0:
            log.info("waiting %.0fs for ingestion", timing.ingest_lag_seconds)
            time.sleep(timing.ingest_lag_seconds)

        # -- stages 5-6: collect and classify --------------------------------
        results = self._collect(
            cases=cases,
            backend=backend,
            compiler=compiler,
            emulation=emulation,
            timing=timing,
            baseline_window=baseline_window,
            live=live,
        )
        record.results = results
        record.finished_at = utcnow()

        # -- stage 7: score ---------------------------------------------------
        coverage = build_coverage(
            record,
            reference=self.workspace.attack,
            targets=self.workspace.targets,
        )
        noise = assess_noise(
            record,
            self.workspace.baselines,
            profile_by_rule={
                rule.name: rule.tuning.baseline_profile
                for rule in self.workspace.rules
                if rule.tuning.baseline_profile
            },
        )

        diff: RunDiff | None = None
        if compare:
            diff = self._compare(record)

        gates = evaluate_gates(
            record, gates_config, diff=diff, coverage=coverage, noise=noise
        )

        return PipelineResult(
            run=record,
            coverage=coverage,
            gates=gates,
            diff=diff,
            noise=noise,
            emulation=emulation,
        )

    def _collect(
        self,
        *,
        cases: Sequence[ValidationCase],
        backend: Backend,
        compiler: QueryCompiler,
        emulation: EmulationOutcome,
        timing,
        baseline_window: TimeWindow,
        live: bool,
    ) -> list[CaseResult]:
        """Query the backend for each case and classify the answer.

        Against a live backend, undetected cases are re-queried until either
        everything fires or the wait budget runs out. That loop is what turns
        "we queried once, too early" into a measured latency.
        """
        observations: dict[str, Observation] = {}
        windows: dict[str, TimeWindow] = {}
        detection_queries: dict[str, CompiledQuery] = {}
        telemetry_queries: dict[str, CompiledQuery | None] = {}

        for case in cases:
            observation = Observation()
            observations[case.case_id] = observation

            if case.skip_reason:
                observation.skip_reason = case.skip_reason
                continue

            observation.emulation = emulation.results.get(case.emulation_id)
            if observation.emulation is None:
                observation.skip_reason = emulation.skipped.get(
                    case.emulation_id, "emulation did not run for this test"
                )
                continue

            rule = self.workspace.rules.get(case.rule_name)
            if rule is None:
                observation.skip_reason = "rule disappeared from the library mid-run"
                continue

            try:
                detection_queries[case.case_id] = compiler.compile(rule)
                telemetry_queries[case.case_id] = compiler.compile_telemetry(rule)
            except CompileError as exc:
                observation.skip_reason = f"rule does not compile for this backend: {exc.message}"
                continue

            # The window must extend past the rule's own latency budget,
            # otherwise a detection that arrives inside its budget but after
            # post_window is reported as a visibility gap - and a breach of the
            # budget could never be observed at all. CloudTrail's batched
            # delivery is the case that makes this bite.
            after = max(timing.post_window_seconds, case.max_latency_seconds) + 60.0
            window = emulation.window_for(case.emulation_id)
            windows[case.case_id] = (
                window.widen(before=timing.pre_window_seconds, after=after)
                if window
                else TimeWindow.last(after)
            )

            observation.queries = {
                "detection": detection_queries[case.case_id].text,
                **(
                    {"telemetry": telemetry_queries[case.case_id].text}
                    if telemetry_queries[case.case_id]
                    else {}
                ),
            }

        # -- detection queries, with polling on live backends ---------------
        pending = list(detection_queries)
        deadline = time.monotonic() + (timing.max_wait_seconds if live else 0.0)
        attempt = 0

        while pending:
            attempt += 1
            still_pending: list[str] = []
            for case_id in pending:
                result = self._search(
                    backend,
                    detection_queries[case_id],
                    windows[case_id],
                    attribution=_attribution(backend, observations[case_id]),
                )
                observations[case_id].detection = result
                if result.ok and not result.events and time.monotonic() < deadline:
                    still_pending.append(case_id)

            pending = still_pending
            if not pending or time.monotonic() >= deadline:
                break
            log.info(
                "%d case(s) not yet detected, re-querying in %.0fs (attempt %d)",
                len(pending),
                timing.poll_interval_seconds,
                attempt,
            )
            time.sleep(timing.poll_interval_seconds)

        # -- telemetry probes and baseline noise ----------------------------
        for case_id, query in telemetry_queries.items():
            if query is None:
                continue
            observations[case_id].telemetry = self._search(
                backend,
                query,
                windows[case_id],
                attribution=_attribution(backend, observations[case_id]),
                limit=1,
            )

        for case_id, query in detection_queries.items():
            observations[case_id].baseline = self._search(
                backend,
                query,
                baseline_window,
                attribution=BASELINE_TEST_ID if isinstance(backend, FixtureBackend) else None,
                limit=25,
            )

        # -- classify --------------------------------------------------------
        results: list[CaseResult] = []
        for case in cases:
            result = classify(
                case,
                observations[case.case_id],
                evidence_limit=self.settings.reporting.evidence_limit,
                redact_fields=self.settings.reporting.redact_fields,
                store_evidence=self.settings.storage.store_evidence,
            )
            results.append(result)
            if self.on_case is not None:
                self.on_case(result)
        return results

    def _search(
        self,
        backend: Backend,
        query: CompiledQuery,
        window: TimeWindow,
        *,
        attribution: str | None = None,
        limit: int | None = None,
    ) -> QueryResult:
        try:
            return backend.search(query, window, limit=limit, attribution=attribution)
        except DvpError as exc:
            return QueryResult.failed(exc.message, query=query.text, backend=backend.name)
        except Exception as exc:
            log.exception("backend %s raised", backend.name)
            return QueryResult.failed(
                f"{type(exc).__name__}: {exc}", query=query.text, backend=backend.name
            )

    def _compiler(self, backend: Backend) -> QueryCompiler:
        config = self.settings.backends.get(backend.name)
        return get_compiler(
            backend.dialect,
            self.workspace.telemetry,
            scope_filter=config.scope_filter if config else "",
        )

    def _compare(self, record: RunRecord) -> RunDiff | None:
        try:
            with self.workspace.store() as store:
                if not store.is_initialised():
                    return None
                previous = store.previous_run(record)
        except DvpError as exc:
            log.warning("could not load the previous run for comparison: %s", exc)
            return None
        return diff_runs(record, previous)


def _attribution(backend: Backend, observation: Observation) -> str | None:
    """Offline replays attribute events to the test that produced them.

    Live platforms cannot: an event carries no marker saying which emulation
    caused it. There, separation comes from the inter-test delay instead.
    """
    if not isinstance(backend, FixtureBackend):
        return None
    return observation.emulation.emulation_id if observation.emulation else None


def default_workspace(root: Path | None = None) -> Workspace:
    return Workspace.load(root)


def resolve_profile(workspace: Workspace, name: str) -> Profile:
    if name in workspace.profiles:
        return workspace.profiles.require(name)
    raise ConfigError(
        f"unknown profile '{name}'",
        hint=f"Available: {', '.join(workspace.profiles.names()) or 'none'}",
    )


def run_metadata(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"generated_at": to_utc(utcnow()).isoformat()}
    payload.update(extra or {})
    return payload
