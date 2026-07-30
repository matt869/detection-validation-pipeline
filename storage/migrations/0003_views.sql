-- 0003_views: read models for the dashboard and the scorecard.
--
-- These exist so the dashboard never has to reimplement "which run counts as
-- current" - a question two consumers would inevitably answer differently.

DROP VIEW IF EXISTS latest_case_outcomes;
CREATE VIEW latest_case_outcomes AS
SELECT c.*, r.started_at AS run_started_at, r.profile AS run_profile
FROM cases c
JOIN runs r ON r.run_id = c.run_id
WHERE r.started_at = (
    SELECT MAX(r2.started_at)
    FROM runs r2
    JOIN cases c2 ON c2.run_id = r2.run_id
    WHERE c2.rule_name = c.rule_name AND c2.emulation_id = c.emulation_id
);

DROP VIEW IF EXISTS rule_history;
CREATE VIEW rule_history AS
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
