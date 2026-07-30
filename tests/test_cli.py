"""CLI behaviour and exit codes.

CI depends on the exit codes being stable and meaningful, so they are asserted
directly rather than inferred from output.
"""

from __future__ import annotations

import json

import pytest

from harness.cli import main
from harness.core.errors import ExitCode


@pytest.fixture(autouse=True)
def _no_colour(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")


def run(*argv: str, root=None) -> int:
    args = ["--root", str(root)] if root else []
    return main([*args, *argv])


# ------------------------------------------------------------------- basics


def test_no_command_prints_help_and_reports_usage(capsys):
    assert main([]) == ExitCode.USAGE
    assert "usage: dvp" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "dvp" in capsys.readouterr().out


def test_unknown_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["nonsense"])
    assert exc.value.code == 2


# ------------------------------------------------------------------- doctor


def test_doctor_passes_on_the_shipped_content(repo_root, capsys):
    assert run("doctor", root=repo_root) == ExitCode.OK
    out = capsys.readouterr().out
    assert "no problems found" in out
    assert "execution is disabled" in out


# -------------------------------------------------------------------- rules


def test_rules_list(repo_root, capsys):
    assert run("rules", "list", root=repo_root) == ExitCode.OK
    assert "lsass_memory_access" in capsys.readouterr().out


def test_rules_list_json_is_parseable(repo_root, capsys):
    run("rules", "list", "--json", root=repo_root)
    payload = json.loads(capsys.readouterr().out)
    assert any(r["name"] == "lsass_memory_access" for r in payload)


def test_rules_list_filters(repo_root, capsys):
    run("rules", "list", "--platform", "aws", root=repo_root)
    out = capsys.readouterr().out
    assert "cloudtrail_logging_disabled" in out
    assert "lsass_memory_access" not in out


def test_rules_show(repo_root, capsys):
    assert run("rules", "show", "lsass_memory_access", root=repo_root) == ExitCode.OK
    out = capsys.readouterr().out
    assert "T1003.001" in out
    assert "sysmon_process_access" in out


def test_rules_show_unknown_reports_a_rule_error(repo_root, capsys):
    assert run("rules", "show", "nope", root=repo_root) == ExitCode.RULE
    assert "no rule named" in capsys.readouterr().err


def test_rules_lint_is_clean(repo_root, capsys):
    assert run("rules", "lint", "--level", "error", root=repo_root) == ExitCode.OK
    assert "0 error(s)" in capsys.readouterr().out


def test_rules_lint_across_dialects(repo_root):
    exit_code = run(
        "rules", "lint", "--level", "error",
        "--dialect", "splunk", "--dialect", "elastic", "--dialect", "fixture",
        root=repo_root,
    )
    assert exit_code == ExitCode.OK


def test_rules_compile(repo_root, capsys):
    assert (
        run("rules", "compile", "lsass_memory_access", "--dialect", "splunk", root=repo_root)
        == ExitCode.OK
    )
    out = capsys.readouterr().out
    assert "index=windows" in out
    assert "NOT" in out


def test_rules_compile_telemetry_probe_has_no_detection_logic(repo_root, capsys):
    run(
        "rules", "compile", "lsass_memory_access",
        "--dialect", "splunk", "--telemetry", root=repo_root,
    )
    out = capsys.readouterr().out
    assert "EventCode=10" in out
    assert "GrantedAccess" not in out


def test_rules_score(repo_root, capsys):
    assert run("rules", "score", root=repo_root) == ExitCode.OK
    assert "library average" in capsys.readouterr().out


def test_rules_score_threshold_can_fail_the_build(repo_root):
    assert run("rules", "score", "--min", "99", root=repo_root) == ExitCode.GATE_FAILED


# -------------------------------------------------------------------- tests


def test_tests_list(repo_root, capsys):
    assert run("tests", "list", root=repo_root) == ExitCode.OK
    assert "T1003.001-lsass-handle-open" in capsys.readouterr().out


def test_tests_show_warns_that_manual_tests_are_operator_run(repo_root, capsys):
    run("tests", "show", "T1003.001-lsass-handle-open", root=repo_root)
    assert "operator-run" in capsys.readouterr().out


# --------------------------------------------------------------------- run


def test_plan_only_executes_nothing(repo_root, capsys):
    assert (
        run("run", "--profile", "quick-smoke", "--plan-only", root=repo_root) == ExitCode.OK
    )
    out = capsys.readouterr().out
    assert "Nothing was executed" in out


def test_offline_run_passes(tmp_path, repo_root, capsys, monkeypatch):
    monkeypatch.setenv("DVP_STORAGE_PATH", str(tmp_path / "run.sqlite3"))
    exit_code = run(
        "run", "--profile", "quick-smoke", "--quiet",
        "--output", str(tmp_path / "reports"),
        root=repo_root,
    )
    assert exit_code == ExitCode.OK
    assert "PASS" in capsys.readouterr().out


def test_run_writes_the_requested_formats(tmp_path, repo_root, monkeypatch):
    monkeypatch.setenv("DVP_STORAGE_PATH", str(tmp_path / "run.sqlite3"))
    reports = tmp_path / "reports"
    run(
        "run", "--profile", "quick-smoke", "--quiet",
        "--format", "json", "--format", "junit",
        "--output", str(reports),
        root=repo_root,
    )
    written = {p.name for p in reports.rglob("*") if p.is_file()}
    assert {"report.json", "junit.xml"} <= written


def test_unknown_profile_is_a_config_error(repo_root, capsys):
    assert run("run", "--profile", "nope", root=repo_root) == ExitCode.CONFIG
    assert "Available profiles" in capsys.readouterr().err


# --------------------------------------------------------------- storage-backed


@pytest.fixture
def populated(tmp_path, repo_root, monkeypatch):
    """A database with one stored run."""
    monkeypatch.setenv("DVP_STORAGE_PATH", str(tmp_path / "dvp.sqlite3"))
    run(
        "run", "--profile", "quick-smoke", "--quiet", "--no-report",
        root=repo_root,
    )
    return repo_root


def test_runs_list(populated, capsys):
    assert run("runs", "list", root=populated) == ExitCode.OK
    assert "quick-smoke" in capsys.readouterr().out


def test_coverage_reports_measured_rates(populated, capsys):
    assert run("coverage", root=populated) == ExitCode.OK
    out = capsys.readouterr().out
    assert "overall detection" in out
    assert "Visibility gaps" in out


def test_coverage_navigator_layer_is_valid(populated, tmp_path, capsys):
    layer_path = tmp_path / "layer.json"
    assert run("coverage", "--navigator", str(layer_path), root=populated) == ExitCode.OK
    layer = json.loads(layer_path.read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"]


def test_coverage_gaps_filter(populated, capsys):
    assert run("coverage", "--gaps", "visibility", root=populated) == ExitCode.OK
    assert "T1562.001" in capsys.readouterr().out


def test_report_latest_to_stdout(populated, capsys):
    assert run("report", "--latest", "--stdout", root=populated) == ExitCode.OK
    assert "Detection validation" in capsys.readouterr().out


def test_db_status(populated, capsys):
    assert run("db", "status", root=populated) == ExitCode.OK
    assert "initialised" in capsys.readouterr().out


def test_db_migrate_is_idempotent(populated, capsys):
    assert run("db", "migrate", root=populated) == ExitCode.OK
    assert "up to date" in capsys.readouterr().out


def test_report_without_any_stored_run_is_a_storage_error(tmp_path, repo_root, monkeypatch, capsys):
    monkeypatch.setenv("DVP_STORAGE_PATH", str(tmp_path / "empty.sqlite3"))
    assert run("report", "--latest", root=repo_root) == ExitCode.STORAGE
    assert "no runs" in capsys.readouterr().err


# ----------------------------------------------------------------- fixtures


def test_fixtures_list(repo_root, capsys):
    assert run("fixtures", "list", root=repo_root) == ExitCode.OK
    assert "credential-theft" in capsys.readouterr().out


def test_fixtures_verify(repo_root, capsys):
    assert run("fixtures", "verify", root=repo_root) == ExitCode.OK
    assert "0 problem(s)" in capsys.readouterr().out
