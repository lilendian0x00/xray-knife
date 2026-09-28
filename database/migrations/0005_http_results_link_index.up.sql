-- Latest HTTP result per config link (database.ConfigsForExport,
-- LatestHttpResults: subs export --status, served subscriptions).
CREATE INDEX IF NOT EXISTS idx_http_test_results_link ON http_test_results(config_link, run_id);
