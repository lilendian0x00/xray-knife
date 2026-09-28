-- The newest HTTP test result of every config link, kept current by the
-- triggers below, so "configs whose latest test passed, fastest first,
-- tested in the last N hours" (subs export, served /sub/<token>) is an
-- indexed lookup instead of a correlated subquery per stored config.
--
-- "Newest" is by run, then by result row: (run_id, result_id) is the
-- largest. run_started is the run's start as "YYYY-MM-DD HH:MM:SS" in UTC,
-- normalised once when the result is written (not on every query) so age
-- filters compare it as plain, indexed text. The expression is
-- database.sqliteTimeKey: datetime() for SQLite/RFC 3339 text, the "+HHMM"
-- offset of time.Time.String() text from earlier releases rewritten as
-- "+HH:MM" first, else the first 19 characters.
CREATE TABLE http_latest_results (
    config_link TEXT PRIMARY KEY,
    result_id INTEGER NOT NULL,
    run_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    delay_ms INTEGER,
    run_started TEXT
) WITHOUT ROWID;

INSERT INTO http_latest_results (config_link, result_id, run_id, status, delay_ms, run_started)
SELECT r.config_link, r.id, r.run_id, r.status, r.delay_ms,
       (SELECT COALESCE(datetime(run.start_time), datetime(substr(run.start_time, 1, 19) || CASE WHEN substr(run.start_time, (20 + instr(substr(run.start_time, 20), ' ')), 5) GLOB '[+-][0-9][0-9][0-9][0-9]' THEN substr(run.start_time, (20 + instr(substr(run.start_time, 20), ' ')), 3) || ':' || substr(run.start_time, (20 + instr(substr(run.start_time, 20), ' ')) + 3, 2) END), replace(substr(run.start_time, 1, 19), 'T', ' ')) FROM http_test_runs run WHERE run.id = r.run_id)
FROM (SELECT id, run_id, config_link, status, delay_ms,
             ROW_NUMBER() OVER (PARTITION BY config_link ORDER BY run_id DESC, id DESC) AS rn
      FROM http_test_results) r
WHERE r.rn = 1;

CREATE INDEX idx_http_latest_status_delay ON http_latest_results(status, delay_ms);
CREATE INDEX idx_http_latest_started ON http_latest_results(run_started);
CREATE INDEX idx_http_latest_run ON http_latest_results(run_id);

-- A new result replaces the link's entry unless the entry is newer.
CREATE TRIGGER http_results_latest_insert AFTER INSERT ON http_test_results
BEGIN
    INSERT OR REPLACE INTO http_latest_results (config_link, result_id, run_id, status, delay_ms, run_started)
    SELECT NEW.config_link, NEW.id, NEW.run_id, NEW.status, NEW.delay_ms,
           (SELECT COALESCE(datetime(start_time), datetime(substr(start_time, 1, 19) || CASE WHEN substr(start_time, (20 + instr(substr(start_time, 20), ' ')), 5) GLOB '[+-][0-9][0-9][0-9][0-9]' THEN substr(start_time, (20 + instr(substr(start_time, 20), ' ')), 3) || ':' || substr(start_time, (20 + instr(substr(start_time, 20), ' ')) + 3, 2) END), replace(substr(start_time, 1, 19), 'T', ' ')) FROM http_test_runs WHERE id = NEW.run_id)
    WHERE NOT EXISTS (
        SELECT 1 FROM http_latest_results l
        WHERE l.config_link = NEW.config_link
          AND (l.run_id > NEW.run_id OR (l.run_id = NEW.run_id AND l.result_id > NEW.id)));
END;

CREATE TRIGGER http_results_latest_update AFTER UPDATE OF status, delay_ms ON http_test_results
BEGIN
    UPDATE http_latest_results SET status = NEW.status, delay_ms = NEW.delay_ms
    WHERE config_link = NEW.config_link AND result_id = NEW.id;
END;

-- Deleting the latest result (db prune, cascades from deleted runs) falls
-- back to the link's next newest result, or drops the entry.
CREATE TRIGGER http_results_latest_delete AFTER DELETE ON http_test_results
WHEN EXISTS (SELECT 1 FROM http_latest_results WHERE config_link = OLD.config_link AND result_id = OLD.id)
BEGIN
    DELETE FROM http_latest_results WHERE config_link = OLD.config_link;
    INSERT INTO http_latest_results (config_link, result_id, run_id, status, delay_ms, run_started)
    SELECT r.config_link, r.id, r.run_id, r.status, r.delay_ms,
           (SELECT COALESCE(datetime(start_time), datetime(substr(start_time, 1, 19) || CASE WHEN substr(start_time, (20 + instr(substr(start_time, 20), ' ')), 5) GLOB '[+-][0-9][0-9][0-9][0-9]' THEN substr(start_time, (20 + instr(substr(start_time, 20), ' ')), 3) || ':' || substr(start_time, (20 + instr(substr(start_time, 20), ' ')) + 3, 2) END), replace(substr(start_time, 1, 19), 'T', ' ')) FROM http_test_runs WHERE id = r.run_id)
    FROM http_test_results r WHERE r.config_link = OLD.config_link
    ORDER BY r.run_id DESC, r.id DESC LIMIT 1;
END;

CREATE TRIGGER http_runs_latest_started AFTER UPDATE OF start_time ON http_test_runs
BEGIN
    UPDATE http_latest_results SET run_started = COALESCE(datetime(NEW.start_time), datetime(substr(NEW.start_time, 1, 19) || CASE WHEN substr(NEW.start_time, (20 + instr(substr(NEW.start_time, 20), ' ')), 5) GLOB '[+-][0-9][0-9][0-9][0-9]' THEN substr(NEW.start_time, (20 + instr(substr(NEW.start_time, 20), ' ')), 3) || ':' || substr(NEW.start_time, (20 + instr(substr(NEW.start_time, 20), ' ')) + 3, 2) END), replace(substr(NEW.start_time, 1, 19), 'T', ' '))
    WHERE run_id = NEW.id;
END;
