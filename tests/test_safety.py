"""The safety policy.

Every test here asserts a refusal. The policy's value is entirely in what it
declines to do, so the failure mode worth guarding against is a check that
silently starts passing.
"""

from __future__ import annotations

import pytest

from harness.core.config import SafetySettings
from harness.emulation.catalog import EmulationTest
from harness.emulation.safety import SafetyPolicy, Target


def make_test(**overrides) -> EmulationTest:
    document = {
        "id": "T1059.001-test",
        "name": "Test",
        "technique": "T1059.001",
        "platform": "windows",
        "executor": "powershell",
        "command": "Write-Output ok",
        "cleanup": "Write-Output done",
        "safe_mode": True,
    }
    document.update(overrides)
    return EmulationTest.from_dict(document)


def authorised(**overrides) -> SafetySettings:
    defaults = {
        "authorized": True,
        "authorization_reference": "CHG-1234",
        "host_allowlist": ["wks-lab-*"],
        "require_cleanup": True,
        "require_lab_tag": True,
    }
    defaults.update(overrides)
    return SafetySettings.from_dict(defaults)


LAB = Target(host="wks-lab-014", platform="windows")


def evaluate(settings, test=None, target=LAB, *, execute=True):
    policy = SafetyPolicy(settings=settings, execution_requested=execute)
    return policy.evaluate(test or make_test(), target)


# ------------------------------------------------------------ default deny


def test_defaults_permit_nothing():
    # A fresh clone must not be able to execute anything.
    allowed, why = SafetyPolicy(
        settings=SafetySettings(), execution_requested=True
    ).execution_enabled()
    assert not allowed
    assert "authorized is false" in why


def test_execute_flag_alone_is_not_enough():
    assert not evaluate(SafetySettings(), execute=True).allowed


def test_configuration_alone_is_not_enough():
    # Editing a YAML file must not be sufficient to start executing.
    assert not evaluate(authorised(), execute=False).allowed


def test_both_keys_together_are_enough():
    assert evaluate(authorised()).allowed


# --------------------------------------------------------------- the checks


def test_authorisation_requires_a_traceable_reference():
    decision = evaluate(authorised(authorization_reference=""))
    assert not decision.allowed
    assert "traceable" in decision.reason


def test_empty_host_allowlist_denies_everything():
    # The inversion that most often goes the other way in security tooling.
    decision = evaluate(authorised(host_allowlist=[]))
    assert not decision.allowed
    assert decision.blocked_by == "host_allowlist"


def test_host_not_on_the_allowlist_is_refused():
    decision = evaluate(authorised(), target=Target(host="srv-prod-01", platform="windows"))
    assert not decision.allowed


def test_host_allowlist_matches_globs_and_short_names():
    settings = authorised(host_allowlist=["wks-lab-*"])
    assert evaluate(
        settings, target=Target(host="wks-lab-014.corp.example", platform="windows")
    ).allowed


def test_non_lab_host_is_refused_by_default():
    settings = authorised(host_allowlist=["*"])
    decision = evaluate(settings, target=Target(host="appserver01", platform="windows"))
    assert not decision.allowed
    assert decision.blocked_by == "lab_tag"


def test_production_naming_raises_a_warning_even_when_allowed():
    settings = authorised(host_allowlist=["*"], require_lab_tag=False)
    decision = evaluate(settings, target=Target(host="srv-prod-lab-01", platform="windows"))
    assert any("production" in w for w in decision.warnings)


def test_denylisted_technique_is_refused():
    decision = evaluate(authorised(), make_test(technique="T1486"))
    assert not decision.allowed
    assert decision.blocked_by == "technique_denylist"


def test_denylist_covers_subtechniques_of_a_listed_parent():
    settings = authorised(technique_denylist=["T1003"])
    assert not evaluate(settings, make_test(technique="T1003.001")).allowed


def test_allowlist_when_present_excludes_everything_else():
    settings = authorised(technique_allowlist=["T1003"])
    assert not evaluate(settings, make_test(technique="T1059.001")).allowed
    assert evaluate(settings, make_test(technique="T1003.001")).allowed


def test_destructive_test_needs_a_third_opt_in():
    destructive = make_test(destructive=True, technique="T1070.001")
    assert not evaluate(authorised(), destructive).allowed
    assert evaluate(authorised(allow_destructive=True), destructive).allowed


def test_test_without_cleanup_is_refused():
    decision = evaluate(authorised(), make_test(cleanup=""))
    assert not decision.allowed
    assert decision.blocked_by == "cleanup_defined"


def test_manual_test_is_never_executed_by_the_harness():
    manual = make_test(executor="manual", command="", cleanup="noop")
    decision = evaluate(authorised(), manual)
    assert not decision.allowed
    assert decision.blocked_by == "executor"


def test_platform_mismatch_is_refused():
    decision = evaluate(
        authorised(host_allowlist=["lab-lnx-*"]),
        make_test(platform="windows"),
        target=Target(host="lab-lnx-02", platform="linux"),
    )
    assert not decision.allowed


def test_failure_budget_stops_a_run_that_is_going_wrong():
    policy = SafetyPolicy(settings=authorised(max_failures=2), execution_requested=True)
    assert policy.evaluate(make_test(), LAB).allowed
    policy.record_failure()
    policy.record_failure()
    decision = policy.evaluate(make_test(), LAB)
    assert not decision.allowed
    assert decision.blocked_by == "failure_budget"


def test_real_technique_test_warns_even_when_permitted():
    decision = evaluate(authorised(), make_test(safe_mode=False))
    assert decision.allowed
    assert any("benign simulation" in w for w in decision.warnings)


# ------------------------------------------------------------- audit trail


def test_every_decision_is_recorded_with_its_checks():
    policy = SafetyPolicy(settings=authorised(), execution_requested=True)
    policy.evaluate(make_test(), LAB)
    policy.evaluate(make_test(id="other", technique="T1486"), LAB)

    trail = policy.audit_trail()
    assert len(trail) == 2
    assert trail[1]["allowed"] is False
    assert trail[1]["blocked_by"] == "technique_denylist"
    assert all(c["name"] for c in trail[0]["checks"])


def test_first_failing_check_is_the_reported_reason():
    # Ordering matters: the operator needs the actionable cause, not the last
    # check that happened to fail.
    decision = evaluate(SafetySettings(), execute=False)
    assert decision.blocked_by == "execution_enabled"


# ------------------------------------------------------------------ target


@pytest.mark.parametrize(
    ("host", "is_lab"),
    [("wks-lab-01", True), ("purple-range-3", True), ("dc01", False), ("appsrv", False)],
)
def test_lab_heuristic(host, is_lab):
    assert Target(host=host).looks_like_lab is is_lab
