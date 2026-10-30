LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_385_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 384 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 384 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=384 AND
        migration_id='384_admin_inbox_messages' AND
        checksum_sha256='5c11871b2ece4b55f9046cb4d43d6793245747bb616aa70f1a2394e1e2187d3c' AND
        down_checksum_sha256='9e97da3f8a96458279a51741ae79e98f771971b9ca7e315778476da5f8d96c62' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_traffic_limits') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 385 requires the exact verified 384 release head' USING ERRCODE='P3850';
    END IF;
END;
$migration_385_up$;

-- ge-analytics (placeholder number; renumbered on merge): a website's own
-- traffic caps (GoEdge TrafficLimitConfig), independent of its package.
-- daily/monthly reset at the period start in the site's time zone; total
-- counts from total_since (set when the total cap is set or changed).
-- Usage is read from ClickHouse access_metering_facts_v1 by the traffic
-- enforcement runtime, which records the decision here (exceeded_period)
-- and republishes the site: every node then answers it with notice_html
-- (509) until the period rolls over or the cap is raised.
CREATE TABLE site_traffic_limits (
    scope_id uuid NOT NULL,
    site_id uuid PRIMARY KEY,
    enabled boolean NOT NULL,
    daily_bytes bigint CHECK (daily_bytes IS NULL OR daily_bytes > 0),
    monthly_bytes bigint CHECK (monthly_bytes IS NULL OR monthly_bytes > 0),
    total_bytes bigint CHECK (total_bytes IS NULL OR total_bytes > 0),
    total_since timestamptz,
    time_zone text NOT NULL CHECK (char_length(time_zone) BETWEEN 1 AND 64),
    notice_html text NOT NULL DEFAULT '' CHECK (octet_length(notice_html) <= 65536),
    exceeded_period text CHECK (exceeded_period IS NULL OR exceeded_period IN ('daily','monthly','total')),
    exceeded_at timestamptz,
    exceeded_period_start timestamptz,
    evaluated_at timestamptz,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    CHECK ((total_bytes IS NULL) = (total_since IS NULL)),
    CHECK ((exceeded_period IS NULL) = (exceeded_at IS NULL) AND (exceeded_period IS NULL) = (exceeded_period_start IS NULL)),
    CHECK (enabled OR exceeded_period IS NULL),
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE INDEX site_traffic_limits_scope_idx ON site_traffic_limits (scope_id);
CREATE INDEX site_traffic_limits_due_idx ON site_traffic_limits (evaluated_at NULLS FIRST) WHERE enabled;

CREATE TABLE site_traffic_limit_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key)
);

CREATE INDEX site_traffic_limit_write_requests_scope_created_idx
    ON site_traffic_limit_write_requests (target_scope_id, created_at DESC);
