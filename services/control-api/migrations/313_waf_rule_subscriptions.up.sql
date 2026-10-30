LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_313_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 312 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 312 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=312 AND
        migration_id='312_node_line_endpoint_published' AND
        checksum_sha256='9ad72f4099c7eb5a449d77b3c38a332a708f517a6f0c67a186e10954d71b109c' AND
        down_checksum_sha256='5a9447177396e87dd56bd2b1b9103744a11fa198a9421d66e6f116e1b0cbc11d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.waf_rule_subscriptions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 313 requires the exact verified 312 release head' USING ERRCODE='P3130';
    END IF;
END;
$migration_313_up$;

-- NF37: global WAF rule libraries fed by a subscription URL (competitor
-- doc.cdnfly.com/docs/WAFfanghu "订阅更新"). Only the control plane fetches
-- the URL (https, public addresses only); a successful fetch is compiled to
-- WAF policy rules and kept as the last good snapshot (revision, rules,
-- feed_version, rules_sha256). A failed fetch only records the error and
-- keeps that snapshot. Tenants subscribe to the library like a platform
-- library (protected "@system/<id>" policy) and publish it through the
-- existing signed activation chain. Deleting only hides the library; the
-- row stays so tenant copies can still be removed.
CREATE TABLE waf_rule_subscriptions (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    source_url text NOT NULL CHECK (char_length(source_url) <= 2048 AND source_url ~ '^https://'),
    interval_minutes integer NOT NULL CHECK (interval_minutes BETWEEN 5 AND 10080),
    enabled boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    feed_version text NOT NULL DEFAULT '' CHECK (char_length(feed_version) <= 128),
    feed_generated_at text NOT NULL DEFAULT '' CHECK (char_length(feed_generated_at) <= 64),
    rules jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(rules) = 'array'),
    rule_count integer NOT NULL DEFAULT 0 CHECK (rule_count BETWEEN 0 AND 100),
    rules_sha256 bytea CHECK (rules_sha256 IS NULL OR octet_length(rules_sha256) = 32),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 1000),
    next_fetch_at timestamptz NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES users(id),
    updated_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CHECK ((revision = 0) = (rules_sha256 IS NULL)),
    CHECK ((revision = 0) = (last_success_at IS NULL))
);
CREATE INDEX waf_rule_subscriptions_due_313_idx ON waf_rule_subscriptions (next_fetch_at)
    WHERE enabled AND deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON waf_rule_subscriptions TO cdnca_control_app, cdnca_control_runtime;
