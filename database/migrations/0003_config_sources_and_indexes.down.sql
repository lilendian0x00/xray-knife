DROP INDEX IF EXISTS idx_http_test_results_run;
DROP INDEX IF EXISTS idx_subscription_configs_protocol;
DROP INDEX IF EXISTS idx_subscription_configs_sub_protocol;
DROP INDEX IF EXISTS idx_subscription_config_sources_config;
DROP TABLE subscription_config_sources;

CREATE TABLE subscription_configs_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER,
    config_link TEXT NOT NULL UNIQUE,
    protocol TEXT,
    remark TEXT,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

INSERT INTO subscription_configs_old (id, subscription_id, config_link, protocol, remark, added_at, last_seen_at)
SELECT id, subscription_id, config_link, protocol, remark, added_at, last_seen_at FROM subscription_configs;

DROP TABLE subscription_configs;

ALTER TABLE subscription_configs_old RENAME TO subscription_configs;
