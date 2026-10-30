LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    -- REQUIRED_MIGRATION_108_INTEGRATION_SHA256=67dc5ddfa5ee3ab8c346c203f4deb1df6af36d7f697830c0b327fb24f3050cd9
    IF (SELECT count(*) FROM schema_migrations) <> 108 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 108 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=108 AND migration_id='108_notification_provider_settlement'
          AND checksum_sha256='8f56c7f03a30c90547edbca9f50da785ed5cf05ddf2395e431c95cb791409ce9'
          AND down_checksum_sha256='63590fa028e8dc35df49171ef6d790b3cb50e136b0fd44f2f0522d405df3a1f9'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 109 requires the exact verified 108 release head'
            USING ERRCODE='P1090';
    END IF;
END;
$$;

CREATE TABLE site_origin_route_configs (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    schema text NOT NULL CHECK (schema = 'cdnca.edge.origin-route/v1'),
    default_pool_id text NOT NULL CHECK (default_pool_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    default_fallback_pool_id text CHECK (
        default_fallback_pool_id IS NULL OR
        (default_fallback_pool_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' AND
         default_fallback_pool_id <> default_pool_id)
    ),
    retry_methods text[] NOT NULL CHECK (
        retry_methods IN (ARRAY['GET']::text[], ARRAY['HEAD']::text[], ARRAY['GET','HEAD']::text[])
    ),
    max_attempts smallint NOT NULL CHECK (max_attempts BETWEEN 1 AND 8),
    connect_timeout_ms integer NOT NULL CHECK (connect_timeout_ms BETWEEN 10 AND 60000),
    read_timeout_ms integer NOT NULL CHECK (read_timeout_ms BETWEEN 10 AND 60000),
    total_budget_ms integer NOT NULL CHECK (
        total_budget_ms BETWEEN connect_timeout_ms + read_timeout_ms AND 120000
    ),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL
);

CREATE TABLE site_origin_route_pools (
    site_id uuid NOT NULL REFERENCES site_origin_route_configs(site_id) ON DELETE CASCADE,
    pool_id text NOT NULL CHECK (pool_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    position smallint NOT NULL CHECK (position BETWEEN 0 AND 63),
    balance_method text NOT NULL CHECK (
        balance_method IN ('round_robin','ip_hash','url_hash','least_conn','random')
    ),
    PRIMARY KEY (site_id, pool_id),
    UNIQUE (site_id, position)
);

CREATE TABLE site_origin_route_endpoints (
    site_id uuid NOT NULL,
    pool_id text NOT NULL,
    endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    position smallint NOT NULL CHECK (position BETWEEN 0 AND 31),
    host inet NOT NULL CHECK (
        host <> '0.0.0.0'::inet AND host <> '::'::inet AND
        host <> '255.255.255.255'::inet AND
        NOT host << '169.254.0.0/16'::inet AND NOT host << 'fe80::/10'::inet AND
        NOT host << '224.0.0.0/4'::inet AND NOT host << 'ff00::/8'::inet
    ),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    weight smallint NOT NULL CHECK (weight BETWEEN 1 AND 100),
    PRIMARY KEY (site_id, pool_id, endpoint_id),
    UNIQUE (site_id, pool_id, position),
    UNIQUE (site_id, pool_id, host, port),
    FOREIGN KEY (site_id, pool_id)
        REFERENCES site_origin_route_pools(site_id, pool_id) ON DELETE CASCADE
);

CREATE TABLE site_origin_routes (
    site_id uuid NOT NULL REFERENCES site_origin_route_configs(site_id) ON DELETE CASCADE,
    route_id text NOT NULL CHECK (route_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    position smallint NOT NULL CHECK (position BETWEEN 0 AND 255),
    priority smallint NOT NULL CHECK (priority BETWEEN -1000 AND 1000),
    path_prefix text CHECK (
        path_prefix IS NULL OR
        (char_length(path_prefix) BETWEEN 1 AND 2048 AND starts_with(path_prefix, '/') AND
         path_prefix !~ '[\\?#%[:cntrl:]]' AND path_prefix !~ '//')
    ),
    node_regions text[] NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(node_regions) <= 32),
    client_cidrs cidr[] NOT NULL DEFAULT '{}'::cidr[] CHECK (cardinality(client_cidrs) <= 32),
    pool_id text NOT NULL,
    fallback_pool_id text,
    PRIMARY KEY (site_id, route_id),
    UNIQUE (site_id, position),
    CHECK (path_prefix IS NOT NULL OR cardinality(node_regions) > 0 OR cardinality(client_cidrs) > 0),
    CHECK (fallback_pool_id IS NULL OR fallback_pool_id <> pool_id),
    FOREIGN KEY (site_id, pool_id)
        REFERENCES site_origin_route_pools(site_id, pool_id) ON DELETE RESTRICT,
    FOREIGN KEY (site_id, fallback_pool_id)
        REFERENCES site_origin_route_pools(site_id, pool_id) ON DELETE RESTRICT
);

CREATE TABLE site_origin_route_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    audit_event_id uuid UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL AND audit_event_id IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL AND audit_event_id IS NOT NULL)
    )
);

CREATE INDEX site_origin_route_write_requests_scope_created_idx
    ON site_origin_route_write_requests (target_scope_id, created_at DESC);

ALTER TABLE site_origin_route_configs
    ADD CONSTRAINT site_origin_route_configs_default_pool_fk
    FOREIGN KEY (site_id, default_pool_id)
    REFERENCES site_origin_route_pools(site_id, pool_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE site_origin_route_configs
    ADD CONSTRAINT site_origin_route_configs_default_fallback_pool_fk
    FOREIGN KEY (site_id, default_fallback_pool_id)
    REFERENCES site_origin_route_pools(site_id, pool_id)
    DEFERRABLE INITIALLY DEFERRED;

REVOKE ALL ON site_origin_route_configs FROM PUBLIC;
REVOKE ALL ON site_origin_route_pools FROM PUBLIC;
REVOKE ALL ON site_origin_route_endpoints FROM PUBLIC;
REVOKE ALL ON site_origin_routes FROM PUBLIC;
REVOKE ALL ON site_origin_route_write_requests FROM PUBLIC;

-- The write path appends this immutable audit action in the same transaction.
COMMENT ON TABLE site_origin_route_write_requests IS
    'Idempotent site.origin_route.update claims bound to request_digest and audit_event_id';
