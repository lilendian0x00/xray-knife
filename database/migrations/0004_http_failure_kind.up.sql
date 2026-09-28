-- Why a config did not pass (pkg/http Result.FailureKind: dns-poisoned,
-- tls-reset, tcp-timeout, ...). NULL for passed results and for rows written
-- before this column existed.
ALTER TABLE http_test_results ADD COLUMN failure_kind TEXT;
