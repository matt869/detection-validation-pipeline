-- 0001_initial: runs, cases, evidence, emulations, coverage, findings.
--
-- Migrations are applied in filename order inside a single transaction each,
-- and recorded in schema_migrations with a checksum. Editing an applied
-- migration is refused at runtime rather than silently ignored - a schema that
-- differs between two operators' machines is worse than a failed upgrade.

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
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT,
    rule_name   TEXT,
    message     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id, kind);
