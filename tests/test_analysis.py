"""Coverage, run diffing, noise assessment, and gates."""

from __future__ import annotations

from harness.analysis.baseline import BaselineProfile, ProfileLibrary, assess_noise
from harness.analysis.coverage import AttackReference, CoverageTargets, build_coverage
from harness.analysis.diff import DeltaKind, diff_runs
from harness.analysis.gates import evaluate_gates
from harness.core.config import GateSettings
from harness.core.models import CaseResult, CaseStatus, Outcome, Severity
from tests.conftest import make_case, make_emulation, make_run


def case_result(
    outcome: Outcome,
    *,
    rule: str = "rule_a",
    emulation: str = "T1059.001-test",
    technique: str = "T1059.001",
    tactic: str = "execution",
    status: CaseStatus = CaseStatus.PASS,
    severity: Severity = Severity.HIGH,
    latency: float | None = None,
    baseline_hits: int = 0,
    telemetry: list[str] | None = None,
) -> CaseResult:
    return CaseResult(
        case=make_case(
            rule_name=rule,
            emulation_id=emulation,
            technique=technique,
            tactic=tactic,
            severity=severity,
            telemetry=telemetry,
        ),
        outcome=outcome,
        status=status,
        latency_seconds=latency,
        baseline_hits=baseline_hits,
        emulation=make_emulation(emulation_id=emulation),
    )


REFERENCE = AttackReference(
    tactics={"execution": {"name": "Execution", "order": 2}},
    techniques={"T1059.001": {"name": "PowerShell", "tactics": ["execution"]}},
    version="16.1",
)
TARGETS = CoverageTargets(
    default_detected=0.7,
    default_visible=0.9,
    tactics={"execution": {"detected": 0.85, "visible": 1.0, "priority": "critical"}},
)


# ---------------------------------------------------------------- coverage


def test_coverage_measures_outcomes_not_rule_counts():
    # Four rules for one technique, none of which fire, is zero coverage.
    run = make_run(
        [case_result(Outcome.VISIBLE, rule=f"rule_{i}") for i in range(4)]
    )
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    technique = coverage.techniques["T1059.001"]
    assert len(technique.rules) == 4
    assert technique.detection_rate == 0.0
    assert technique.status == "detection-gap"


def test_visibility_rate_counts_telemetry_not_alerts():
    run = make_run([case_result(Outcome.VISIBLE), case_result(Outcome.DETECTED, rule="b")])
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    assert coverage.detection_rate == 0.5
    assert coverage.visibility_rate == 1.0


def test_blind_technique_names_the_missing_source():
    run = make_run([case_result(Outcome.BLIND, telemetry=["windows_defender_operational"])])
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    technique = coverage.techniques["T1059.001"]
    assert technique.status == "visibility-gap"
    assert technique.missing_telemetry == ("windows_defender_operational",)


def test_operational_outcomes_do_not_distort_rates():
    run = make_run(
        [
            case_result(Outcome.DETECTED),
            case_result(Outcome.ERROR, rule="b"),
            case_result(Outcome.SKIPPED, rule="c"),
        ]
    )
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    # One scoreable case, and it was detected.
    assert coverage.techniques["T1059.001"].scoreable == 1
    assert coverage.detection_rate == 1.0


def test_tactic_targets_are_applied():
    run = make_run([case_result(Outcome.DETECTED), case_result(Outcome.VISIBLE, rule="b")])
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    tactic = coverage.tactics["execution"]
    assert tactic.target_detected == 0.85
    assert tactic.detection_rate == 0.5
    assert not tactic.meets_target


def test_excluded_techniques_are_omitted():
    targets = CoverageTargets(excluded={"T1059.001": "owned by the email team"})
    run = make_run([case_result(Outcome.DETECTED)])
    coverage = build_coverage(run, reference=REFERENCE, targets=targets)
    assert "T1059.001" not in coverage.techniques


# -------------------------------------------------------------------- diff


def test_detection_becoming_visible_is_a_regression():
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([case_result(Outcome.VISIBLE)], run_id="run-2")
    diff = diff_runs(current, previous)
    assert len(diff.regressions) == 1
    assert diff.regressions[0].kind is DeltaKind.REGRESSION
    assert "no longer matches" in diff.regressions[0].note


def test_detection_becoming_blind_blames_collection():
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([case_result(Outcome.BLIND)], run_id="run-2")
    assert "check collection" in diff_runs(current, previous).regressions[0].note


def test_improvement_is_recorded_but_is_not_a_regression():
    previous = make_run([case_result(Outcome.BLIND)], run_id="run-1")
    current = make_run([case_result(Outcome.DETECTED)], run_id="run-2")
    diff = diff_runs(current, previous)
    assert not diff.regressions
    assert len(diff.improvements) == 1


def test_unchanged_cases_are_omitted_by_default():
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([case_result(Outcome.DETECTED)], run_id="run-2")
    assert diff_runs(current, previous).changed == []


def test_operational_states_never_count_as_regressions():
    # A backend outage is not a detection regression.
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([case_result(Outcome.ERROR)], run_id="run-2")
    assert not diff_runs(current, previous).regressions


def test_materially_slower_detection_is_flagged():
    previous = make_run([case_result(Outcome.DETECTED, latency=10)], run_id="run-1")
    current = make_run([case_result(Outcome.DETECTED, latency=200)], run_id="run-2")
    assert diff_runs(current, previous).of_kind(DeltaKind.SLOWER)


def test_removed_case_is_reported():
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([], run_id="run-2")
    assert diff_runs(current, previous).of_kind(DeltaKind.REMOVED)


def test_first_run_reports_only_gaps_not_every_case():
    current = make_run(
        [case_result(Outcome.DETECTED), case_result(Outcome.BLIND, rule="b")]
    )
    diff = diff_runs(current, None)
    assert len(diff.deltas) == 1
    assert diff.deltas[0].rule_name == "b"


# ------------------------------------------------------------------- noise


def test_noise_beyond_the_accepted_allowance_is_a_finding():
    library = ProfileLibrary(
        profiles={
            "windows-workstation": BaselineProfile.from_dict(
                {
                    "name": "windows-workstation",
                    "accepted_noise": [{"rule": "rule_a", "max_hits": 2, "reason": "Teams"}],
                }
            )
        }
    )
    run = make_run([case_result(Outcome.DETECTED, baseline_hits=5)])
    findings = assess_noise(run, library, profile_by_rule={"rule_a": "windows-workstation"})
    assert findings[0].excess == 3


def test_noise_within_the_allowance_is_not_a_finding():
    library = ProfileLibrary(
        profiles={
            "p": BaselineProfile.from_dict(
                {"name": "p", "accepted_noise": [{"rule": "rule_a", "max_hits": 5}]}
            )
        }
    )
    run = make_run([case_result(Outcome.DETECTED, baseline_hits=2)])
    assert assess_noise(run, library, profile_by_rule={"rule_a": "p"}) == []


def test_unaccepted_noise_is_always_a_finding():
    # No profile means an allowance of zero: the way to stop noise being a
    # finding is to write down why it is acceptable.
    run = make_run([case_result(Outcome.DETECTED, baseline_hits=1)])
    assert assess_noise(run, ProfileLibrary(), profile_by_rule={})


def test_a_rule_can_be_detected_and_noisy_at_once():
    run = make_run([case_result(Outcome.DETECTED, baseline_hits=3)])
    assert run.results[0].outcome is Outcome.DETECTED
    assert run.results[0].is_noisy


# ------------------------------------------------------------------- gates


def test_expectation_failures_fail_the_build():
    run = make_run([case_result(Outcome.VISIBLE, status=CaseStatus.FAIL)])
    outcome = evaluate_gates(run, GateSettings())
    assert not outcome.passed
    assert not next(g for g in outcome.results if g.name == "expectations-met").passed


def test_accepted_gaps_do_not_fail_the_build():
    run = make_run([case_result(Outcome.BLIND, status=CaseStatus.PASS)])
    assert evaluate_gates(run, GateSettings()).passed


def test_severity_floor_protects_the_build_from_low_severity_noise():
    run = make_run(
        [case_result(Outcome.VISIBLE, status=CaseStatus.FAIL, severity=Severity.LOW)]
    )
    settings = GateSettings(min_severity=Severity.HIGH)
    assert evaluate_gates(run, settings).passed


def test_errors_fail_by_default():
    run = make_run([case_result(Outcome.ERROR, status=CaseStatus.ERROR)])
    assert not evaluate_gates(run, GateSettings()).passed


def test_rate_gates_are_inapplicable_when_the_threshold_is_zero():
    run = make_run([case_result(Outcome.VISIBLE)])
    outcome = evaluate_gates(run, GateSettings(min_detection_rate=0))
    assert not next(g for g in outcome.results if g.name == "detection-rate").applicable


def test_detection_rate_gate_fires_below_the_threshold():
    run = make_run([case_result(Outcome.VISIBLE), case_result(Outcome.DETECTED, rule="b")])
    outcome = evaluate_gates(run, GateSettings(min_detection_rate=0.9))
    assert not outcome.passed
    assert "50%" in next(g for g in outcome.results if g.name == "detection-rate").message


def test_coverage_gate_is_off_unless_explicitly_enabled():
    # A coverage target is an estate-wide assertion; most profiles are subsets.
    run = make_run([case_result(Outcome.VISIBLE)])
    coverage = build_coverage(run, reference=REFERENCE, targets=TARGETS)
    default = evaluate_gates(run, GateSettings(), coverage=coverage)
    enabled = evaluate_gates(
        run, GateSettings(fail_on_coverage_target=True), coverage=coverage
    )
    assert default.passed
    assert not enabled.passed


def test_regression_gate_uses_the_diff():
    previous = make_run([case_result(Outcome.DETECTED)], run_id="run-1")
    current = make_run([case_result(Outcome.VISIBLE)], run_id="run-2")
    diff = diff_runs(current, previous)
    assert not evaluate_gates(current, GateSettings(), diff=diff).passed


def test_latency_gate_is_opt_in():
    run = make_run([case_result(Outcome.DETECTED, latency=9999)])
    assert evaluate_gates(run, GateSettings()).passed
    assert not evaluate_gates(run, GateSettings(fail_on_latency_breach=True)).passed


def test_failing_gates_name_the_offenders():
    run = make_run([case_result(Outcome.VISIBLE, status=CaseStatus.FAIL, rule="noisy_rule")])
    gate = next(
        g for g in evaluate_gates(run, GateSettings()).results if g.name == "expectations-met"
    )
    assert any("noisy_rule" in o for o in gate.offenders)
