-- A config link can come from several subscriptions. Until now each row had
-- one subscription_id (the last subscription that returned it) with
-- ON DELETE CASCADE, so removing one subscription deleted links another
-- subscription still provides. Track every source in its own table, and
-- rebuild subscription_configs so its subscription_id (kept as "most recent
-- source" for display) is SET NULL instead of cascading.

CREATE TABLE subscription_configs_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER,
    config_link TEXT NOT NULL UNIQUE,
    protocol TEXT,
    remark TEXT,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
);

-- Rows may point at subscriptions that no longer exist (written while
-- foreign keys were off); copying those ids verbatim would fail the
-- constraint and leave the migration dirty, so they become NULL (one-off).
INSERT INTO subscription_configs_new (id, subscription_id, config_link, protocol, remark, added_at, last_seen_at)
SELECT id,
       CASE WHEN subscription_id IN (SELECT id FROM subscriptions) THEN subscription_id END,
       config_link, protocol, remark, added_at, last_seen_at
FROM subscription_configs;

DROP TABLE subscription_configs;

ALTER TABLE subscription_configs_new RENAME TO subscription_configs;

CREATE TABLE subscription_config_sources (
    subscription_id INTEGER NOT NULL,
    config_id INTEGER NOT NULL,
    last_seen_at DATETIME,
    PRIMARY KEY (subscription_id, config_id),
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    FOREIGN KEY(config_id) REFERENCES subscription_configs(id) ON DELETE CASCADE
);

INSERT INTO subscription_config_sources (subscription_id, config_id, last_seen_at)
SELECT subscription_id, id, last_seen_at FROM subscription_configs
WHERE subscription_id IS NOT NULL AND subscription_id IN (SELECT id FROM subscriptions);

CREATE INDEX idx_subscription_config_sources_config ON subscription_config_sources(config_id);
CREATE INDEX idx_subscription_configs_sub_protocol ON subscription_configs(subscription_id, protocol);
CREATE INDEX idx_subscription_configs_protocol ON subscription_configs(protocol);
CREATE INDEX idx_http_test_results_run ON http_test_results(run_id);
