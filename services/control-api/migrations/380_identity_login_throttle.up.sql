LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_380_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 379 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 379 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=379 AND
        migration_id='379_site_origin_forwarding' AND
        checksum_sha256='8d00f648a22b4081a1a60002a7a67dd13be97ac1125e59c081c1bcd0faef2b58' AND
        down_checksum_sha256='2fb1f5193ad0fb705078190bd24c1d659337a4879e281b39d07b55cd9a3cac62' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.identity_login_attempts') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 380 requires the exact verified 379 release head' USING ERRCODE='P3800';
    END IF;
END;
$migration_380_up$;

-- r136 ge-account (placeholder number 380, guard on the 379 head; renumbered
-- on merge): password sign-in throttling and the built-in sign-in CAPTCHA
-- (GoEdge comparison G8, missing item 2 / logic item 4). The platform settings
-- login_failure_limit_per_hour and login_captcha_threshold_per_hour are
-- enforced from these facts.
--   * identity_login_attempts: one row per password attempt that passed the
--     throttle. It is written before the password is checked (so parallel
--     attempts cannot pass the limit together), deleted when the attempt turns
--     out not to be a credential failure, and the account+source rows are
--     cleared by a successful sign-in. Rows older than the one-hour window are
--     pruned by the writer.
--   * identity_login_captchas: one-time built-in CAPTCHA challenges. Only the
--     keyed digest of the answer is stored.
CREATE TABLE identity_login_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_digest bytea NOT NULL CHECK (octet_length(account_digest) = 32),
    source_ip text NOT NULL CHECK (char_length(source_ip) <= 45),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at))
);
CREATE INDEX identity_login_attempts_account_380_idx ON identity_login_attempts (account_digest, occurred_at);
CREATE INDEX identity_login_attempts_source_380_idx ON identity_login_attempts (source_ip, occurred_at);
CREATE INDEX identity_login_attempts_time_380_idx ON identity_login_attempts (occurred_at);

CREATE TABLE identity_login_captchas (
    id uuid PRIMARY KEY,
    answer_digest bytea NOT NULL CHECK (octet_length(answer_digest) = 32),
    source_ip text NOT NULL CHECK (char_length(source_ip) <= 45),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > created_at),
    consumed_at timestamptz CHECK (consumed_at IS NULL OR isfinite(consumed_at))
);
CREATE INDEX identity_login_captchas_source_380_idx ON identity_login_captchas (source_ip, created_at);
CREATE INDEX identity_login_captchas_expiry_380_idx ON identity_login_captchas (expires_at);

REVOKE ALL ON identity_login_attempts, identity_login_captchas FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON identity_login_attempts TO cdnca_control_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_login_captchas TO cdnca_control_app;
