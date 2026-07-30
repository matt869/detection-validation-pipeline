"""SQLite persistence for validation runs.

SQLite rather than a server database, deliberately: the history of a detection
programme is a few thousand rows a year, it needs to be greppable, backup-able,
and openable on a laptop during an incident review. Nothing here needs a
cluster.

Writes are one transaction per run - a partially-stored run would report
regressions that never happened.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.analysis.coverage import CoverageReport
from harness.analysis.gates import GateOutcome
from harness.core.errors import StorageError
from harness.core.logging import get_logger
from harness.core.models import (
    AttackRef,
    CaseResult,
    CaseStatus,
    Confidence,
    EmulationResult,
    Outcome,
    RunRecord,
    Severity,
    ValidationCase,
)
from harness.core.timeutil import parse_ts, to_iso, utcnow

__all__ = ["Store", "StoredRun"]

log = get_logger("store")


@dataclass(frozen=True, slots=True)
class StoredRun:
    """Row-level summary of a run, without loading its cases."""

    run_id: str
    profile: str
    backend: str
    mode: str
    started_at: str
    finished_at: str | None
    total_cases: int
    detected: int
    visible: int
    blind: int
    detection_rate: float
    visibility_rate: float
    gates_passed: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "backend": self.backend,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_cases": self.total_cases,
            "detected": self.detected,
            "visible": self.visible,
            "blind": self.blind,
            "detection_rate": self.detection_rate,
            "visibility_rate": self.visibility_rate,
            "gates_passed": self.gates_passed,
        }


class Store:
    """Repository over the run database."""

    def __init__(self, path: Path | str, *, migrations_dir: Path | str | None = None) -> None:
        self.path = Path(path)
        self.migrations_dir = Path(migrations_dir) if migrations_dir else None
        self._connection: sqlite3.Connection | None = None

    # -- connection --------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            # WAL keeps the dashboard readable while a run is being written.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            self._connection = connection
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> Store:
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        connection.execute("BEGIN")
        try:
            yield connection
        except Exception:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")

    # -- migrations --------------------------------------------------------

    def migrate(self, *, dry_run: bool = False) -> list[str]:
        """Apply pending migrations in filename order. Returns what was applied.

        A migration whose content changed after being applied is an error, not
        a warning: two machines silently running different schemas produces
        results that cannot be compared, which defeats the point of the tool.

        SQLite's ``executescript`` commits any open transaction before it runs,
        so a migration cannot be wrapped in one. Every statement is therefore
        written to be idempotent (``IF NOT EXISTS`` / ``DROP ... IF EXISTS``),
        and the version row is only recorded once the script has succeeded - a
        half-applied migration is re-runnable rather than wedged.
        """
        directory = self.migrations_dir
        if directory is None or not directory.exists():
            raise StorageError(
                f"migrations directory not found: {directory}",
                hint="Expected storage/migrations/*.sql",
            )

        connection = self.connect()
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL, checksum TEXT NOT NULL)"
        )
        applied = {
            row["version"]: row["checksum"]
            for row in connection.execute("SELECT version, checksum FROM schema_migrations")
        }

        performed: list[str] = []
        for path in sorted(directory.glob("*.sql")):
            version = path.stem
            body = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]

            if version in applied:
                if applied[version] != checksum:
                    raise StorageError(
                        f"migration {version} has changed since it was applied "
                        f"(recorded {applied[version]}, file {checksum})",
                        hint="Add a new migration instead of editing an applied one. "
                        "To start over: delete the database and re-run.",
                    )
                continue

            if dry_run:
                performed.append(version)
                continue

            log.info("applying migration %s", version)
            try:
                connection.executescript(body)
            except sqlite3.Error as exc:
                raise StorageError(
                    f"migration {version} failed: {exc}",
                    hint="Migrations are idempotent; fix the SQL and re-run `dvp db migrate`.",
                ) from exc
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at, checksum) VALUES (?, ?, ?)",
                (version, to_iso(utcnow()), checksum),
            )
            performed.append(version)

        return performed

    def applied_versions(self) -> list[str]:
        connection = self.connect()
        try:
            rows = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [row["version"] for row in rows]

    def is_initialised(self) -> bool:
        connection = self.connect()
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='runs'"
        ).fetchone()
        return row is not None

    # -- writing -----------------------------------------------------------

    def save_run(
        self,
        run: RunRecord,
        *,
        coverage: CoverageReport | None = None,
        gates: GateOutcome | None = None,
        rule_scores: Mapping[str, tuple[str, float, str]] | None = None,
        findings: Iterable[Mapping[str, Any]] = (),
        store_evidence: bool = True,
    ) -> None:
        """Persist a complete run. Replaces any existing row with the same id."""
        if not self.is_initialised():
            self.migrate()

        summary = run.summarise()
        with self.transaction() as tx:
            tx.execute("DELETE FROM runs WHERE run_id = ?", (run.run_id,))
            tx.execute(
                """
                INSERT INTO runs (
                    run_id, profile, backend, mode, operator, git_ref,
                    started_at, finished_at, duration_seconds,
                    total_cases, detected, visible, blind, errored, skipped,
                    detection_rate, visibility_rate, latency_p50, latency_p95,
                    gates_passed, metadata
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run.run_id,
                    run.profile,
                    run.backend,
                    run.mode,
                    run.operator,
                    run.git_ref,
                    to_iso(run.started_at),
                    to_iso(run.finished_at),
                    run.duration_seconds,
                    summary.total,
                    summary.by_outcome.get("detected", 0),
                    summary.by_outcome.get("visible", 0),
                    summary.by_outcome.get("blind", 0),
                    summary.by_outcome.get("error", 0),
                    summary.by_outcome.get("skipped", 0),
                    summary.detection_rate,
                    summary.visibility_rate,
                    summary.latency_p50,
                    summary.latency_p95,
                    None if gates is None else int(gates.passed),
                    json.dumps(run.metadata, default=str),
                ),
            )

            for result in run.results:
                self._insert_case(tx, run.run_id, result, store_evidence=store_evidence)

            for result in run.results:
                emulation = result.emulation
                if emulation is None:
                    continue
                tx.execute(
                    """
                    INSERT OR REPLACE INTO emulations (
                        run_id, emulation_id, executed, mode, host,
                        started_at, finished_at, exit_code, cleanup_performed, error
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        run.run_id,
                        emulation.emulation_id,
                        int(emulation.executed),
                        emulation.mode,
                        emulation.host,
                        to_iso(emulation.started_at),
                        to_iso(emulation.finished_at),
                        emulation.exit_code,
                        int(emulation.cleanup_performed),
                        emulation.error,
                    ),
                )

            if coverage is not None:
                for technique in coverage.techniques.values():
                    tx.execute(
                        """
                        INSERT OR REPLACE INTO coverage_snapshots (
                            run_id, technique, name, tactics, detected, visible, blind,
                            detection_rate, visibility_rate, target_detected,
                            target_visible, priority, status
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            run.run_id,
                            technique.technique,
                            technique.name,
                            json.dumps(list(technique.tactics)),
                            technique.detected,
                            technique.visible,
                            technique.blind,
                            technique.detection_rate,
                            technique.visibility_rate,
                            technique.target_detected,
                            technique.target_visible,
                            technique.priority,
                            technique.status,
                        ),
                    )

            for name, (fingerprint, score, grade) in (rule_scores or {}).items():
                tx.execute(
                    """
                    INSERT OR REPLACE INTO rule_snapshots
                        (run_id, rule_name, fingerprint, status, severity, score, grade)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (run.run_id, name, fingerprint, None, None, score, grade),
                )

            if gates is not None:
                for gate in gates.results:
                    if gate.applicable and not gate.passed:
                        tx.execute(
                            "INSERT INTO findings (run_id, kind, name, severity, "
                            "rule_name, message, detail) VALUES (?,?,?,?,?,?,?)",
                            (
                                run.run_id,
                                "gate",
                                gate.name,
                                "high",
                                None,
                                gate.message,
                                json.dumps({"offenders": list(gate.offenders)}),
                            ),
                        )

            for finding in findings:
                tx.execute(
                    "INSERT INTO findings (run_id, kind, name, severity, "
                    "rule_name, message, detail) VALUES (?,?,?,?,?,?,?)",
                    (
                        run.run_id,
                        str(finding.get("kind", "finding")),
                        str(finding.get("name", "")),
                        finding.get("severity"),
                        finding.get("rule"),
                        str(finding.get("message", "")),
                        json.dumps(finding.get("detail") or {}, default=str),
                    ),
                )

        log.info("stored run %s (%d cases)", run.run_id, len(run.results))

    def _insert_case(
        self,
        tx: sqlite3.Connection,
        run_id: str,
        result: CaseResult,
        *,
        store_evidence: bool,
    ) -> None:
        case = result.case
        tx.execute(
            """
            INSERT OR REPLACE INTO cases (
                run_id, case_id, rule_name, rule_id, rule_title, severity, platform,
                emulation_id, backend, expected, outcome, status, confidence,
                detection_hits, telemetry_hits, baseline_hits, latency_seconds,
                max_latency_seconds, first_detection_at, telemetry, notes, queries, error
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id,
                case.case_id,
                case.rule_name,
                case.rule_id,
                case.rule_title,
                case.severity.value,
                case.platform,
                case.emulation_id,
                case.backend,
                case.expected.value,
                result.outcome.value,
                result.status.value,
                result.confidence.value,
                result.detection_hits,
                result.telemetry_hits,
                result.baseline_hits,
                result.latency_seconds,
                case.max_latency_seconds,
                to_iso(result.first_detection_at),
                json.dumps(list(case.telemetry)),
                json.dumps(list(result.notes)),
                json.dumps(dict(result.queries)),
                result.error,
            ),
        )

        for ref in case.attack:
            if not ref.technique:
                continue
            tx.execute(
                "INSERT OR REPLACE INTO case_attack (run_id, case_id, technique, tactic) "
                "VALUES (?,?,?,?)",
                (run_id, case.case_id, ref.technique, ref.tactic),
            )

        if store_evidence:
            for ordinal, document in enumerate(result.evidence):
                tx.execute(
                    "INSERT OR REPLACE INTO evidence (run_id, case_id, ordinal, document) "
                    "VALUES (?,?,?,?)",
                    (run_id, case.case_id, ordinal, json.dumps(document, default=str)),
                )

    # -- reading -----------------------------------------------------------

    def list_runs(
        self,
        *,
        limit: int = 25,
        profile: str | None = None,
        backend: str | None = None,
    ) -> list[StoredRun]:
        clauses: list[str] = []
        params: list[Any] = []
        if profile:
            clauses.append("profile = ?")
            params.append(profile)
        if backend:
            clauses.append("backend = ?")
            params.append(backend)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        rows = self.connect().execute(
            f"SELECT * FROM runs {where} ORDER BY started_at DESC LIMIT ?",
            (*params, limit),
        )
        return [_stored_run(row) for row in rows]

    def latest_run_id(self, *, profile: str | None = None, before: str | None = None) -> str | None:
        clauses: list[str] = []
        params: list[Any] = []
        if profile:
            clauses.append("profile = ?")
            params.append(profile)
        if before:
            clauses.append("run_id != ?")
            params.append(before)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = (
            self.connect()
            .execute(f"SELECT run_id FROM runs {where} ORDER BY started_at DESC LIMIT 1", params)
            .fetchone()
        )
        return row["run_id"] if row else None

    def load_run(self, run_id: str) -> RunRecord | None:
        connection = self.connect()
        run_row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run_row is None:
            return None

        emulations = {
            row["emulation_id"]: EmulationResult(
                emulation_id=row["emulation_id"],
                executed=bool(row["executed"]),
                mode=row["mode"],
                host=row["host"] or "unknown",
                started_at=parse_ts(row["started_at"]),
                finished_at=parse_ts(row["finished_at"]),
                exit_code=row["exit_code"],
                cleanup_performed=bool(row["cleanup_performed"]),
                error=row["error"],
            )
            for row in connection.execute("SELECT * FROM emulations WHERE run_id = ?", (run_id,))
        }

        attack: dict[str, list[AttackRef]] = {}
        for row in connection.execute("SELECT * FROM case_attack WHERE run_id = ?", (run_id,)):
            attack.setdefault(row["case_id"], []).append(
                AttackRef(technique=row["technique"], tactic=row["tactic"])
            )

        evidence: dict[str, list[dict[str, Any]]] = {}
        for row in connection.execute(
            "SELECT * FROM evidence WHERE run_id = ? ORDER BY ordinal", (run_id,)
        ):
            evidence.setdefault(row["case_id"], []).append(json.loads(row["document"]))

        results: list[CaseResult] = []
        for row in connection.execute(
            "SELECT * FROM cases WHERE run_id = ? ORDER BY rule_name", (run_id,)
        ):
            case = ValidationCase(
                case_id=row["case_id"],
                rule_name=row["rule_name"],
                rule_id=row["rule_id"] or "",
                rule_title=row["rule_title"] or row["rule_name"],
                severity=Severity.parse(row["severity"], default=Severity.MEDIUM),
                attack=attack.get(row["case_id"], []),
                platform=row["platform"] or "unknown",
                emulation_id=row["emulation_id"],
                backend=row["backend"] or run_row["backend"],
                expected=Outcome(row["expected"]),
                telemetry=json.loads(row["telemetry"] or "[]"),
                max_latency_seconds=row["max_latency_seconds"] or 300.0,
            )
            results.append(
                CaseResult(
                    case=case,
                    outcome=Outcome(row["outcome"]),
                    status=CaseStatus(row["status"]),
                    confidence=Confidence(row["confidence"]),
                    detection_hits=row["detection_hits"],
                    telemetry_hits=row["telemetry_hits"],
                    baseline_hits=row["baseline_hits"],
                    latency_seconds=row["latency_seconds"],
                    first_detection_at=parse_ts(row["first_detection_at"]),
                    emulation=emulations.get(row["emulation_id"]),
                    evidence=evidence.get(row["case_id"], []),
                    notes=json.loads(row["notes"] or "[]"),
                    error=row["error"],
                    queries=json.loads(row["queries"] or "{}"),
                )
            )

        return RunRecord(
            run_id=run_row["run_id"],
            profile=run_row["profile"],
            backend=run_row["backend"],
            started_at=parse_ts(run_row["started_at"]) or utcnow(),
            finished_at=parse_ts(run_row["finished_at"]),
            mode=run_row["mode"],
            operator=run_row["operator"] or "unknown",
            git_ref=run_row["git_ref"],
            results=results,
            metadata=json.loads(run_row["metadata"] or "{}"),
        )

    def previous_run(self, run: RunRecord) -> RunRecord | None:
        """The most recent run of the same profile before this one."""
        row = (
            self.connect()
            .execute(
                "SELECT run_id FROM runs WHERE profile = ? AND started_at < ? "
                "ORDER BY started_at DESC LIMIT 1",
                (run.profile, to_iso(run.started_at)),
            )
            .fetchone()
        )
        return self.load_run(row["run_id"]) if row else None

    def rule_history(self, rule_name: str, *, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.connect().execute(
            "SELECT * FROM rule_history WHERE rule_name = ? ORDER BY started_at DESC LIMIT ?",
            (rule_name, limit),
        )
        return [dict(row) for row in rows][::-1]

    def latest_outcomes(self) -> dict[str, str]:
        """Rule name -> most recent outcome, used by the scorecard."""
        try:
            rows = (
                self.connect()
                .execute("SELECT rule_name, outcome, run_started_at FROM latest_case_outcomes")
                .fetchall()
            )
        except sqlite3.OperationalError:
            return {}

        # A rule with several tests takes its worst recent outcome: claiming a
        # rule works because one of its three tests fired would be generous in
        # exactly the wrong direction.
        rank = {"blind": 0, "visible": 1, "detected": 2}
        worst: dict[str, str] = {}
        for row in rows:
            outcome = row["outcome"]
            if outcome not in rank:
                continue
            current = worst.get(row["rule_name"])
            if current is None or rank[outcome] < rank[current]:
                worst[row["rule_name"]] = outcome
        return worst

    def findings(self, run_id: str, *, kind: str | None = None) -> list[dict[str, Any]]:
        clause = "AND kind = ?" if kind else ""
        params: Sequence[Any] = (run_id, kind) if kind else (run_id,)
        rows = self.connect().execute(
            f"SELECT * FROM findings WHERE run_id = ? {clause} ORDER BY id", params
        )
        return [dict(row) for row in rows]

    # -- maintenance -------------------------------------------------------

    def prune(self, *, keep_days: int) -> int:
        """Delete runs older than ``keep_days``. Cascades to every child table."""
        cutoff = utcnow().timestamp() - keep_days * 86400
        cutoff_iso = to_iso(parse_ts(cutoff))
        with self.transaction() as tx:
            cursor = tx.execute("DELETE FROM runs WHERE started_at < ?", (cutoff_iso,))
            deleted = cursor.rowcount or 0
        if deleted:
            self.connect().execute("VACUUM")
        return deleted

    def stats(self) -> dict[str, Any]:
        connection = self.connect()
        if not self.is_initialised():
            return {"initialised": False, "path": str(self.path)}
        counts = {
            table: connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            for table in ("runs", "cases", "findings", "coverage_snapshots")
        }
        oldest = connection.execute("SELECT MIN(started_at) AS t FROM runs").fetchone()["t"]
        newest = connection.execute("SELECT MAX(started_at) AS t FROM runs").fetchone()["t"]
        return {
            "initialised": True,
            "path": str(self.path),
            "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "migrations": self.applied_versions(),
            "oldest_run": oldest,
            "newest_run": newest,
            **counts,
        }


def _stored_run(row: sqlite3.Row) -> StoredRun:
    gates = row["gates_passed"]
    return StoredRun(
        run_id=row["run_id"],
        profile=row["profile"],
        backend=row["backend"],
        mode=row["mode"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        total_cases=row["total_cases"],
        detected=row["detected"],
        visible=row["visible"],
        blind=row["blind"],
        detection_rate=row["detection_rate"],
        visibility_rate=row["visibility_rate"],
        gates_passed=None if gates is None else bool(gates),
    )
