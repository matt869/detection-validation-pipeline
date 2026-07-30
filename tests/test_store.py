"""Persistence: migrations and run round-tripping."""

from __future__ import annotations

import pytest

from harness.analysis.coverage import AttackReference, CoverageTargets, build_coverage
from harness.analysis.gates import evaluate_gates
from harness.core.config import GateSettings
from harness.core.errors import StorageError
from harness.core.models import CaseResult, CaseStatus, Confidence, Outcome
from harness.store import Store
from tests.conftest import make_case, make_emulation, make_run


@pytest.fixture
def store(tmp_path, repo_root) -> Store:
    store = Store(tmp_path / "test.sqlite3", migrations_dir=repo_root / "storage" / "migrations")
    store.migrate()
    yield store
    store.close()


def result(outcome=Outcome.DETECTED, **kwargs) -> CaseResult:
    return CaseResult(
        case=make_case(**{k: v for k, v in kwargs.items() if k in {"rule_name", "emulation_id"}}),
        outcome=outcome,
        status=CaseStatus.PASS,
        confidence=Confidence.HIGH,
        detection_hits=kwargs.get("detection_hits", 2),
        telemetry_hits=kwargs.get("telemetry_hits", 5),
        baseline_hits=kwargs.get("baseline_hits", 0),
        latency_seconds=kwargs.get("latency", 4.5),
        emulation=make_emulation(),
        evidence=[{"CommandLine": "cmd.exe /c whoami"}],
        notes=["a note"],
        queries={"detection": "index=windows EventCode=1"},
    )


# -------------------------------------------------------------- migrations


def test_migrations_apply_in_order(tmp_path, repo_root):
    store = Store(tmp_path / "db.sqlite3", migrations_dir=repo_root / "storage" / "migrations")
    applied = store.migrate()
    assert applied == sorted(applied)
    assert "0001_initial" in applied
    assert store.is_initialised()
    store.close()


def test_migrations_are_idempotent(store):
    assert store.migrate() == []


def test_dry_run_reports_without_applying(tmp_path, repo_root):
    store = Store(tmp_path / "db.sqlite3", migrations_dir=repo_root / "storage" / "migrations")
    pending = store.migrate(dry_run=True)
    assert pending
    assert not store.is_initialised()
    store.close()


def test_edited_migration_is_a_hard_error(tmp_path, repo_root):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001_x.sql").write_text("CREATE TABLE IF NOT EXISTS runs (a TEXT);")

    store = Store(tmp_path / "db.sqlite3", migrations_dir=migrations)
    store.migrate()

    # Two machines silently running different schemas produce results that
    # cannot be compared, so this fails rather than warning.
    (migrations / "0001_x.sql").write_text("CREATE TABLE IF NOT EXISTS runs (b TEXT);")
    with pytest.raises(StorageError, match="has changed since it was applied"):
        store.migrate()
    store.close()


def test_missing_migrations_directory_is_an_error(tmp_path):
    store = Store(tmp_path / "db.sqlite3", migrations_dir=tmp_path / "nope")
    with pytest.raises(StorageError, match="migrations directory not found"):
        store.migrate()


def test_views_are_created(store):
    names = {
        row[0]
        for row in store.connect().execute("SELECT name FROM sqlite_master WHERE type='view'")
    }
    assert {"latest_case_outcomes", "rule_history"} <= names


# ------------------------------------------------------------ round-tripping


def test_run_round_trips(store):
    run = make_run([result(), result(Outcome.VISIBLE, rule_name="rule_b")])
    store.save_run(run)

    loaded = store.load_run(run.run_id)
    assert loaded is not None
    assert len(loaded.results) == 2
    assert {r.outcome for r in loaded.results} == {Outcome.DETECTED, Outcome.VISIBLE}
    assert loaded.summarise().detection_rate == 0.5


def test_case_detail_survives_the_round_trip(store):
    run = make_run([result()])
    store.save_run(run)
    loaded = store.load_run(run.run_id).results[0]

    assert loaded.detection_hits == 2
    assert loaded.telemetry_hits == 5
    assert loaded.latency_seconds == 4.5
    assert loaded.notes == ["a note"]
    assert loaded.queries["detection"] == "index=windows EventCode=1"
    assert loaded.evidence[0]["CommandLine"] == "cmd.exe /c whoami"
    assert loaded.case.technique_ids == ["T1059.001"]


def test_evidence_can_be_withheld(store):
    run = make_run([result()])
    store.save_run(run, store_evidence=False)
    assert store.load_run(run.run_id).results[0].evidence == []


def test_saving_the_same_run_id_replaces_it(store):
    run = make_run([result()], run_id="run-same")
    store.save_run(run)
    store.save_run(make_run([result(), result(rule_name="b")], run_id="run-same"))
    assert len(store.load_run("run-same").results) == 2


def test_coverage_snapshot_is_persisted(store):
    run = make_run([result()])
    coverage = build_coverage(
        run, reference=AttackReference.empty(), targets=CoverageTargets.empty()
    )
    store.save_run(run, coverage=coverage)
    rows = store.connect().execute("SELECT technique, status FROM coverage_snapshots").fetchall()
    assert rows[0]["technique"] == "T1059.001"


def test_failing_gates_become_findings(store):
    run = make_run(
        [
            CaseResult(
                case=make_case(),
                outcome=Outcome.VISIBLE,
                status=CaseStatus.FAIL,
                emulation=make_emulation(),
            )
        ]
    )
    gates = evaluate_gates(run, GateSettings())
    store.save_run(run, gates=gates)

    findings = store.findings(run.run_id, kind="gate")
    assert any(f["name"] == "expectations-met" for f in findings)


def test_deleting_a_run_cascades(store):
    run = make_run([result()])
    store.save_run(run)
    store.connect().execute("DELETE FROM runs WHERE run_id = ?", (run.run_id,))
    remaining = store.connect().execute(
        "SELECT COUNT(*) AS n FROM cases WHERE run_id = ?", (run.run_id,)
    ).fetchone()["n"]
    assert remaining == 0


# ------------------------------------------------------------------ queries


def test_previous_run_is_the_prior_run_of_the_same_profile(store):
    first = make_run([result()], run_id="run-1", profile="alpha")
    store.save_run(first)

    second = make_run([result()], run_id="run-2", profile="alpha")
    second.started_at = first.started_at.replace(microsecond=0)
    from datetime import timedelta

    second.started_at = first.started_at + timedelta(minutes=5)
    store.save_run(second)

    other = make_run([result()], run_id="run-3", profile="beta")
    store.save_run(other)

    assert store.previous_run(second).run_id == "run-1"


def test_latest_outcomes_takes_the_worst_per_rule(store):
    # A rule whose three tests disagree is only as good as its worst result.
    run = make_run(
        [
            result(Outcome.DETECTED, rule_name="rule_x", emulation_id="t1"),
            result(Outcome.BLIND, rule_name="rule_x", emulation_id="t2"),
        ]
    )
    store.save_run(run)
    assert store.latest_outcomes()["rule_x"] == "blind"


def test_rule_history_is_chronological(store):
    from datetime import timedelta

    first = make_run([result(rule_name="rule_h")], run_id="run-1")
    second = make_run([result(Outcome.VISIBLE, rule_name="rule_h")], run_id="run-2")
    second.started_at = first.started_at + timedelta(minutes=1)
    store.save_run(first)
    store.save_run(second)

    history = store.rule_history("rule_h")
    assert [row["outcome"] for row in history] == ["detected", "visible"]


def test_list_runs_filters_by_profile(store):
    store.save_run(make_run([result()], run_id="run-a", profile="alpha"))
    store.save_run(make_run([result()], run_id="run-b", profile="beta"))
    assert [r.run_id for r in store.list_runs(profile="beta")] == ["run-b"]


def test_stats_on_a_fresh_database(tmp_path, repo_root):
    store = Store(tmp_path / "new.sqlite3", migrations_dir=repo_root / "storage" / "migrations")
    assert store.stats()["initialised"] is False
    store.close()


def test_missing_run_returns_none(store):
    assert store.load_run("run-does-not-exist") is None
