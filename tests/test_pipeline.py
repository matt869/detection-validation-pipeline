"""End-to-end pipeline runs against the repository's own content.

These are the tests that would catch a break in the seams between stages -
emulation windows not reaching the backend, attribution not applied, coverage
computed from the wrong run.
"""

from __future__ import annotations

import pytest

from harness.core.models import CaseStatus, Outcome
from harness.pipeline import Pipeline, PipelineResult


@pytest.fixture(scope="module")
def smoke_result(request) -> PipelineResult:
    """One offline run of the shipped quick-smoke profile, reused module-wide."""
    from harness.pipeline import Workspace

    workspace = Workspace.load()
    pipeline = Pipeline(workspace)
    return pipeline.run(
        workspace.profiles.require("quick-smoke"),
        execute=False,
        compare=False,
        operator="pytest",
    )


# -------------------------------------------------------------------- plan


def test_plan_produces_one_case_per_rule_and_test(workspace):
    pipeline = Pipeline(workspace)
    profile = workspace.profiles.require("quick-smoke")
    cases = pipeline.plan(profile)

    assert cases
    # lsass_memory_access declares two emulation tests, so it must yield two
    # cases: each variant of a technique is proven separately.
    lsass = [c for c in cases if c.rule_name == "lsass_memory_access"]
    assert len(lsass) == 2


def test_plan_case_ids_are_deterministic(workspace):
    pipeline = Pipeline(workspace)
    profile = workspace.profiles.require("quick-smoke")
    first = {c.case_id for c in pipeline.plan(profile, run_id="run-fixed")}
    second = {c.case_id for c in pipeline.plan(profile, run_id="run-fixed")}
    assert first == second


def test_plan_carries_the_rule_expectation(workspace):
    pipeline = Pipeline(workspace)
    cases = pipeline.plan(workspace.profiles.require("quick-smoke"))
    defender = next(c for c in cases if c.rule_name == "defender_exclusion_added")
    assert defender.expected is Outcome.BLIND


def test_plan_only_executes_nothing(workspace):
    pipeline = Pipeline(workspace)
    result = pipeline.run(workspace.profiles.require("quick-smoke"), plan_only=True, compare=False)
    assert result.plan_only
    assert result.run.results == []


# --------------------------------------------------------------------- run


def test_offline_run_produces_results(smoke_result):
    assert len(smoke_result.run.results) > 0
    assert smoke_result.run.mode == "replay"
    assert smoke_result.run.finished_at is not None


def test_offline_run_executes_no_commands(smoke_result):
    assert smoke_result.emulation is not None
    assert smoke_result.emulation.executed_count() == 0


def test_shipped_corpora_produce_detections(smoke_result):
    detected = [r for r in smoke_result.run.results if r.outcome is Outcome.DETECTED]
    assert len(detected) >= 10


def test_no_case_errors_offline(smoke_result):
    errored = [r for r in smoke_result.run.results if r.outcome is Outcome.ERROR]
    assert errored == [], [r.error for r in errored]


def test_every_case_matches_its_documented_expectation(smoke_result):
    # The shipped content is internally consistent: every rule's declared
    # expectation matches what the recorded telemetry actually produces.
    failures = [r for r in smoke_result.run.results if r.status is CaseStatus.FAIL]
    assert failures == [], [
        f"{r.case.rule_name}: expected {r.case.expected.value}, got {r.outcome.value}"
        for r in failures
    ]


def test_documented_visibility_gap_reports_blind_and_passes(smoke_result):
    defender = next(
        r for r in smoke_result.run.results if r.case.rule_name == "defender_exclusion_added"
    )
    assert defender.outcome is Outcome.BLIND
    assert defender.status is CaseStatus.PASS
    assert defender.outcome.gap_kind == "visibility"


def test_latency_is_measured_from_the_recorded_offsets(smoke_result):
    lsass = next(
        r for r in smoke_result.run.results if r.case.emulation_id == "T1003.001-lsass-handle-open"
    )
    # The corpus records the malicious handle open at +9s.
    assert lsass.latency_seconds == pytest.approx(9.0, abs=1.0)


def test_cloud_latency_survives_a_window_wider_than_post_window(smoke_result):
    # CloudTrail delivery is batched; the recorded offset exceeds the default
    # post_window, so the window has to stretch to the rule's latency budget.
    root_login = next(
        r for r in smoke_result.run.results if r.case.rule_name == "root_console_login"
    )
    assert root_login.outcome is Outcome.DETECTED
    assert root_login.latency_seconds > 300


def test_attribution_prevents_cross_test_credit(smoke_result):
    # mshta and rundll32 both produce Sysmon EID 1 within seconds of each other.
    # Without attribution one would be credited with the other's telemetry.
    mshta = next(r for r in smoke_result.run.results if r.case.rule_name == "mshta_remote_payload")
    assert mshta.detection_hits == 1


def test_baseline_noise_is_measured(smoke_result):
    # run_key_persistence matches a Teams autostart entry in the baseline
    # corpus. A rule can be detected and noisy at the same time.
    run_key = next(r for r in smoke_result.run.results if r.case.rule_name == "run_key_persistence")
    assert run_key.outcome is Outcome.DETECTED
    assert run_key.is_noisy
    assert run_key.baseline_hits == 1


def test_accepted_noise_is_measured_but_not_reported_as_a_finding(smoke_result):
    # windows-workstation accepts up to 2 hits for this rule, with a reason, an
    # owner and a review date. Measuring it and reporting it are different
    # things: the hit still shows on the case, but nobody is paged for it.
    run_key = next(r for r in smoke_result.run.results if r.case.rule_name == "run_key_persistence")
    assert run_key.is_noisy
    assert [f for f in smoke_result.noise if f.rule == "run_key_persistence"] == []


def test_noise_beyond_the_allowance_would_be_a_finding(workspace, smoke_result):
    from harness.analysis.baseline import assess_noise

    # Same run, but with no accepted allowance: the hit becomes a finding.
    findings = assess_noise(smoke_result.run, workspace.baselines, profile_by_rule={})
    assert any(f.rule == "run_key_persistence" for f in findings)


def test_quiet_rules_are_not_flagged_noisy(smoke_result):
    lsass = next(r for r in smoke_result.run.results if r.case.rule_name == "lsass_memory_access")
    assert not lsass.is_noisy


# ---------------------------------------------------------------- analysis


def test_coverage_is_computed(smoke_result):
    coverage = smoke_result.coverage
    assert coverage is not None
    assert coverage.techniques
    assert 0.0 < coverage.detection_rate <= 1.0


def test_coverage_names_the_missing_telemetry(smoke_result):
    blind = [t for t in smoke_result.coverage.techniques.values() if t.blind]
    assert blind
    assert any(t.missing_telemetry for t in blind)


def test_quick_smoke_gates_pass(smoke_result):
    assert smoke_result.gates is not None
    assert smoke_result.passed, smoke_result.gates.summary()


def test_summary_arithmetic_is_consistent(smoke_result):
    summary = smoke_result.run.summarise()
    scoreable = sum(summary.by_outcome.get(o, 0) for o in ("detected", "visible", "blind"))
    assert summary.total == sum(summary.by_outcome.values())
    assert summary.detection_rate == pytest.approx(
        summary.by_outcome.get("detected", 0) / scoreable
    )


# ---------------------------------------------------------- persistence loop


def test_run_survives_a_store_round_trip(tmp_workspace):
    pipeline = Pipeline(tmp_workspace)
    result = pipeline.run(
        tmp_workspace.profiles.require("quick-smoke"), compare=False, operator="pytest"
    )
    with tmp_workspace.store() as store:
        store.save_run(result.run, coverage=result.coverage, gates=result.gates)
        loaded = store.load_run(result.run.run_id)

    assert loaded is not None
    assert len(loaded.results) == len(result.run.results)
    assert loaded.summarise().by_outcome == result.run.summarise().by_outcome


def test_second_run_diffs_against_the_first(tmp_workspace):
    pipeline = Pipeline(tmp_workspace)
    profile = tmp_workspace.profiles.require("quick-smoke")

    first = pipeline.run(profile, compare=False, operator="pytest")
    with tmp_workspace.store() as store:
        store.save_run(first.run)

    second = pipeline.run(profile, compare=True, operator="pytest")
    assert second.diff is not None
    assert second.diff.baseline_run_id == first.run.run_id
    # Nothing changed between two identical replays.
    assert second.diff.regressions == []


def test_reports_render_from_a_real_run(tmp_path, smoke_result):
    from harness.reporting import FORMATS, write_reports

    written = write_reports(
        smoke_result.run,
        tmp_path,
        formats=FORMATS,
        coverage=smoke_result.coverage,
        gates=smoke_result.gates,
        noise=smoke_result.noise,
    )
    assert len(written) == len(FORMATS)
    assert all(p.stat().st_size > 500 for p in written)


# -------------------------------------------------------------- other profiles


@pytest.mark.parametrize("profile_name", ["credential-theft", "ransomware-precursor"])
def test_every_shipped_profile_runs(workspace, profile_name):
    pipeline = Pipeline(workspace)
    result = pipeline.run(
        workspace.profiles.require(profile_name), compare=False, operator="pytest"
    )
    assert result.run.results
    assert not [r for r in result.run.results if r.outcome is Outcome.ERROR]


def test_ransomware_profile_exercises_all_three_states(workspace):
    # The profile spans a whole attack chain, so it is the one that shows the
    # model working end to end.
    pipeline = Pipeline(workspace)
    result = pipeline.run(
        workspace.profiles.require("ransomware-precursor"), compare=False, operator="pytest"
    )
    observed = {r.outcome for r in result.run.results}
    assert {Outcome.DETECTED, Outcome.VISIBLE, Outcome.BLIND} <= observed


def test_documented_detection_gap_reports_visible(workspace):
    pipeline = Pipeline(workspace)
    result = pipeline.run(
        workspace.profiles.require("ransomware-precursor"), compare=False, operator="pytest"
    )
    rdp = next(r for r in result.run.results if r.case.rule_name == "rdp_logon_from_workstation")
    # Telemetry arrived; the over-broad exclusion swallowed it.
    assert rdp.outcome is Outcome.VISIBLE
    assert rdp.status is CaseStatus.PASS
    assert rdp.telemetry_hits > 0
    assert rdp.detection_hits == 0
