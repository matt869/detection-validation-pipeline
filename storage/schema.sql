-- Reference snapshot of the full schema.
--
-- This file is documentation, not the thing that runs. The database is built by
-- applying storage/migrations/*.sql in order. If this file and the migrations
-- disagree, the migrations win; regenerate with `dvp db schema`.
--
-- Design notes:
--
--   * One row per case per run. Runs are never updated in place - a re-run is
--     a new run - so historical results stay reproducible.
--   * Rule metadata is denormalised onto `cases`. A rule can be edited or
--     deleted after a run; the report must still describe what was actually
--     validated, not what the rule says today.
--   * Outcome and status are separate columns for the same reason they are
--     separate concepts: `visible`/`pass` is a documented gap, `visible`/`fail`
--     is a broken detection, and collapsing them loses the distinction.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TEXT NOT NULL,
    checksum    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id            TEXT PRIMARY KEY,
    profile           TEXT NOT NULL,
    backend           TEXT NOT NULL,
    mode              TEXT NOT NULL,
    operator          TEXT,
    git_ref           TEXT,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    duration_seconds  REAL,
    total_cases       INTEGER NOT NULL DEFAULT 0,
    detected          INTEGER NOT NULL DEFAULT 0,
    visible           INTEGER NOT NULL DEFAULT 0,
    blind             INTEGER NOT NULL DEFAULT 0,
    errored           INTEGER NOT NULL DEFAULT 0,
    skipped           INTEGER NOT NULL DEFAULT 0,
    detection_rate    REAL NOT NULL DEFAULT 0,
    visibility_rate   REAL NOT NULL DEFAULT 0,
    latency_p50       REAL,
    latency_p95       REAL,
    gates_passed      INTEGER,
    metadata          TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_runs_profile_started ON runs (profile, started_at DESC);

CREATE TABLE IF NOT EXISTS cases (
    run_id              TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    case_id             TEXT NOT NULL,
    rule_name           TEXT NOT NULL,
    rule_id             TEXT,
    rule_title          TEXT,
    severity            TEXT NOT NULL,
    platform            TEXT,
    emulation_id        TEXT NOT NULL,
    backend             TEXT,
    expected            TEXT NOT NULL,
    outcome             TEXT NOT NULL,
    status              TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    detection_hits      INTEGER NOT NULL DEFAULT 0,
    telemetry_hits      INTEGER NOT NULL DEFAULT 0,
    baseline_hits       INTEGER NOT NULL DEFAULT 0,
    latency_seconds     REAL,
    max_latency_seconds REAL,
    first_detection_at  TEXT,
    telemetry           TEXT NOT NULL DEFAULT '[]',
    notes               TEXT NOT NULL DEFAULT '[]',
    queries             TEXT NOT NULL DEFAULT '{}',
    error               TEXT,
    PRIMARY KEY (run_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_cases_rule ON cases (rule_name, run_id);
CREATE INDEX IF NOT EXISTS idx_cases_outcome ON cases (outcome);
CREATE INDEX IF NOT EXISTS idx_cases_emulation ON cases (emulation_id);

CREATE TABLE IF NOT EXISTS case_attack (
    run_id      TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    technique   TEXT NOT NULL,
    tactic      TEXT,
    PRIMARY KEY (run_id, case_id, technique),
    FOREIGN KEY (run_id, case_id) REFERENCES cases (run_id, case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_attack_technique ON case_attack (technique);

CREATE TABLE IF NOT EXISTS evidence (
    run_id    TEXT NOT NULL,
    case_id   TEXT NOT NULL,
    ordinal   INTEGER NOT NULL,
    document  TEXT NOT NULL,
    PRIMARY KEY (run_id, case_id, ordinal),
    FOREIGN KEY (run_id, case_id) REFERENCES cases (run_id, case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS emulations (
    run_id            TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    emulation_id      TEXT NOT NULL,
    executed          INTEGER NOT NULL DEFAULT 0,
    mode              TEXT NOT NULL,
    host              TEXT,
    started_at        TEXT,
    finished_at       TEXT,
    exit_code         INTEGER,
    cleanup_performed INTEGER NOT NULL DEFAULT 0,
    error             TEXT,
    PRIMARY KEY (run_id, emulation_id)
);

CREATE TABLE IF NOT EXISTS coverage_snapshots (
    run_id           TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    technique        TEXT NOT NULL,
    name             TEXT,
    tactics          TEXT NOT NULL DEFAULT '[]',
    detected         INTEGER NOT NULL DEFAULT 0,
    visible          INTEGER NOT NULL DEFAULT 0,
    blind            INTEGER NOT NULL DEFAULT 0,
    detection_rate   REAL NOT NULL DEFAULT 0,
    visibility_rate  REAL NOT NULL DEFAULT 0,
    target_detected  REAL NOT NULL DEFAULT 0,
    target_visible   REAL NOT NULL DEFAULT 0,
    priority         TEXT,
    status           TEXT NOT NULL,
    PRIMARY KEY (run_id, technique)
);

CREATE INDEX IF NOT EXISTS idx_coverage_status ON coverage_snapshots (status, priority);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,          -- gate | noise | regression | error
    name        TEXT NOT NULL,
    severity    TEXT,
    rule_name   TEXT,
    message     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id, kind);

CREATE TABLE IF NOT EXISTS rule_snapshots (
    run_id       TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    rule_name    TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    status       TEXT,
    severity     TEXT,
    score        REAL,
    grade        TEXT,
    PRIMARY KEY (run_id, rule_name)
);

-- Most recent outcome per rule/test pair. The dashboard landing page and
-- `dvp rules score` read this instead of re-scanning every run.
CREATE VIEW IF NOT EXISTS latest_case_outcomes AS
SELECT c.*, r.started_at AS run_started_at, r.profile AS run_profile
FROM cases c
JOIN runs r ON r.run_id = c.run_id
WHERE r.started_at = (
    SELECT MAX(r2.started_at)
    FROM runs r2
    JOIN cases c2 ON c2.run_id = r2.run_id
    WHERE c2.rule_name = c.rule_name AND c2.emulation_id = c.emulation_id
);

-- Outcome trend per rule, oldest first. Used to draw sparklines.
CREATE VIEW IF NOT EXISTS rule_history AS
SELECT
    c.rule_name,
    r.run_id,
    r.started_at,
    r.profile,
    c.emulation_id,
    c.outcome,
    c.status,
    c.latency_seconds
FROM cases c
JOIN runs r ON r.run_id = c.run_id
ORDER BY r.started_at ASC;
