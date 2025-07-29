CREATE TABLE subscriptions (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               url TEXT NOT NULL UNIQUE,
                               remark TEXT,
                               user_agent TEXT,
                               enabled BOOLEAN NOT NULL DEFAULT 1,
                               last_fetched_at DATETIME,
                               created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE subscription_configs (
                                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                                      subscription_id INTEGER,
                                      config_link TEXT NOT NULL UNIQUE,
                                      protocol TEXT,
                                      remark TEXT,
                                      added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                      last_seen_at DATETIME,
                                      FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE TABLE http_test_runs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                start_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                end_time DATETIME,
                                options_json TEXT,
                                config_count INTEGER
);

CREATE TABLE http_test_results (
                                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                                   run_id INTEGER NOT NULL,
                                   config_link TEXT NOT NULL,
                                   status TEXT NOT NULL,
                                   reason TEXT,
                                   delay_ms INTEGER,
                                   download_mbps REAL,
                                   upload_mbps REAL,
                                   ip_address TEXT,
                                   ip_location TEXT,
                                   FOREIGN KEY(run_id) REFERENCES http_test_runs(id) ON DELETE CASCADE
);

CREATE TABLE cf_scan_results (
                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                 ip TEXT NOT NULL UNIQUE,
                                 latency_ms INTEGER,
                                 download_mbps REAL,
                                 upload_mbps REAL,
                                 error TEXT,
                                 last_scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);