-- 0002_rule_snapshots: record the rule library's state at run time.
--
-- Without this, a report from three months ago cannot answer "was this rule
-- different then?". The fingerprint covers detection logic only, so editing a
-- description does not make it look like the rule changed behaviour.

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

CREATE INDEX IF NOT EXISTS idx_rule_snapshots_name ON rule_snapshots (rule_name);
