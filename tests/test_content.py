"""Checks on the content that ships in this repository.

The rules, emulation tests, telemetry catalogue and corpora are content, not
code - but they are the part most likely to drift, and a broken cross-reference
between them is invisible until a run reports a gap that is not real. These
tests make that drift fail the build.
"""

from __future__ import annotations

import pytest

from harness.core.models import Outcome, RuleStatus
from rulekit.compilers import get_compiler
from rulekit.linters import Level, LintContext, run_linters, summarise

DIALECTS = ("fixture", "splunk", "elastic")


# ------------------------------------------------------------------ loading


def test_every_rule_file_parses(workspace):
    assert workspace.rules.errors == []
    assert len(workspace.rules) > 0


def test_no_duplicate_rule_ids(workspace):
    assert workspace.rules.duplicate_ids() == {}


def test_every_rule_declares_telemetry(workspace):
    # Without this the three-state model degrades to guessing.
    missing = [r.name for r in workspace.rules if not r.telemetry]
    assert missing == []


def test_every_declared_telemetry_source_exists(workspace):
    unknown = {
        source
        for rule in workspace.rules
        for source in rule.telemetry
        if source not in workspace.telemetry
    }
    assert unknown == set()


def test_every_rule_has_at_least_one_emulation_test(workspace):
    untested = [r.name for r in workspace.rules if not r.validation.emulation]
    assert untested == []


def test_every_referenced_emulation_test_exists(workspace):
    unknown = {
        test_id
        for rule in workspace.rules
        for test_id in rule.validation.emulation
        if test_id not in workspace.tests
    }
    assert unknown == set()


def test_every_technique_is_in_the_attack_mapping(workspace):
    unmapped = {
        technique
        for rule in workspace.rules
        for technique in rule.technique_ids
        if technique and technique not in workspace.attack.techniques
    }
    assert unmapped == set()


def test_accepted_gaps_are_owned_and_justified(workspace):
    for rule in workspace.rules:
        if rule.validation.expect is not Outcome.DETECTED:
            assert rule.validation.justification, f"{rule.name} has no justification"
            assert rule.validation.owner, f"{rule.name} has no owner"


def test_referenced_baseline_profiles_exist(workspace):
    unknown = {
        rule.tuning.baseline_profile
        for rule in workspace.rules
        if rule.tuning.baseline_profile
        and workspace.baselines.get(rule.tuning.baseline_profile) is None
    }
    assert unknown == set()


# ---------------------------------------------------------------- compiling


@pytest.mark.parametrize("dialect", DIALECTS)
def test_every_rule_compiles_for_every_shipped_dialect(workspace, dialect):
    compiler = get_compiler(dialect, workspace.telemetry)
    for rule in workspace.rules:
        compiler.compile(rule)


@pytest.mark.parametrize("dialect", DIALECTS)
def test_every_rule_has_a_telemetry_probe(workspace, dialect):
    compiler = get_compiler(dialect, workspace.telemetry)
    without = [r.name for r in workspace.rules if compiler.compile_telemetry(r) is None]
    assert without == []


def test_negations_survive_compilation(workspace):
    # The regression that matters most: a rule that silently loses its
    # exclusion clause alerts on everything.
    compiler = get_compiler("splunk", workspace.telemetry)
    for rule in workspace.rules:
        if any(n.startswith(("filter", "exclude")) for n in rule.selections):
            assert "NOT" in compiler.compile(rule).text, rule.name


# ------------------------------------------------------------------ linting


def test_shipped_rules_have_no_lint_errors(workspace):
    context = LintContext(
        catalog=workspace.telemetry,
        known_tests=workspace.tests.ids(),
        attack=workspace.attack.techniques,
        required_dialects=DIALECTS,
        library_names=frozenset(workspace.rules.rules),
        root=workspace.settings.root,
    )
    findings = run_linters(workspace.rules, context, min_level=Level.ERROR)
    assert findings == [], "\n".join(f.format() for f in findings)


def test_lint_warning_count_is_bounded(workspace):
    # Warnings are allowed - some are deliberate trade-offs recorded in the
    # rules themselves - but a sudden jump means something regressed.
    context = LintContext(
        catalog=workspace.telemetry,
        known_tests=workspace.tests.ids(),
        attack=workspace.attack.techniques,
        required_dialects=DIALECTS,
    )
    counts = summarise(run_linters(workspace.rules, context))
    assert counts["warning"] <= 40, counts


def test_linters_do_not_crash_on_any_rule(workspace):
    context = LintContext(catalog=workspace.telemetry, required_dialects=DIALECTS)
    findings = run_linters(workspace.rules, context)
    assert not [f for f in findings if f.code == "LN000"]


# --------------------------------------------------------- emulation tests


def test_shipped_tests_are_safe_or_operator_run(workspace):
    # A test that runs the real technique automatically has no place in a
    # repository other people clone.
    for test in workspace.tests:
        assert test.safe_mode or test.requires_operator, (
            f"{test.id} runs the real technique but is not marked executor: manual"
        )


def test_automated_tests_define_cleanup(workspace):
    for test in workspace.tests:
        if not test.requires_operator:
            assert test.has_cleanup, f"{test.id} has no cleanup"


def test_destructive_tests_are_operator_run(workspace):
    for test in workspace.tests:
        if test.destructive:
            assert test.requires_operator, f"{test.id} is destructive and automated"


def test_no_test_targets_a_denylisted_technique(workspace):
    denied = set(workspace.settings.safety.technique_denylist)
    for test in workspace.tests:
        parent = test.technique.split(".", 1)[0]
        assert test.technique not in denied and parent not in denied


def test_every_test_is_referenced_by_a_rule(workspace):
    referenced = set(workspace.rules.by_emulation())
    orphans = {t.id for t in workspace.tests} - referenced
    assert orphans == set()


# ------------------------------------------------------------------ profiles


def test_every_profile_selects_at_least_one_rule(workspace):
    from harness.pipeline import Pipeline

    pipeline = Pipeline(workspace)
    for profile in workspace.profiles:
        assert pipeline.plan(profile), f"profile '{profile.name}' selects nothing"


def test_profile_scenarios_exist(workspace):
    available = {p.name for p in workspace.settings.layout.fixture_runs.iterdir() if p.is_dir()}
    for profile in workspace.profiles:
        unknown = set(profile.scenarios) - available
        assert unknown == set(), f"{profile.name} references missing corpora: {unknown}"


def test_profile_backends_are_configured(workspace):
    for profile in workspace.profiles:
        if profile.backend:
            assert profile.backend in workspace.settings.backends


# ------------------------------------------------------------------ safety


def test_impact_techniques_are_denylisted_by_default(workspace):
    denied = set(workspace.settings.safety.technique_denylist)
    assert {"T1485", "T1486", "T1489", "T1490", "T1561"} <= denied


def test_shipped_settings_do_not_authorise_execution(workspace):
    # A fresh clone must not be able to execute anything.
    assert workspace.settings.safety.authorized is False
    assert workspace.settings.safety.host_allowlist == ()


# ------------------------------------------------------- telemetry catalogue


def test_telemetry_sources_map_every_shipped_dialect(workspace):
    used = {source for rule in workspace.rules for source in rule.telemetry}
    for source_id in sorted(used):
        source = workspace.telemetry.require(source_id)
        for dialect in DIALECTS:
            assert source.supports(dialect), f"{source_id} has no {dialect} mapping"


def test_telemetry_sources_have_owners(workspace):
    used = {source for rule in workspace.rules for source in rule.telemetry}
    without = [s for s in used if not workspace.telemetry.require(s).owner]
    assert without == []


def test_production_rules_are_the_majority(workspace):
    production = [r for r in workspace.rules if r.status is RuleStatus.PRODUCTION]
    assert len(production) >= len(workspace.rules) // 2
