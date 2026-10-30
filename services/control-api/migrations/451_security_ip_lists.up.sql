LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_451_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 450 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 450 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=450 AND
        migration_id='450_waf_adapt_node_limits' AND
        checksum_sha256='057dfb35fa99e6cd96d0be3dc34d1677cb9a1c7591d7e4bb2eda02aa99e6bea5' AND
        down_checksum_sha256='9365c964108bf3a8a77e547911d5108c5576f777951cf41d6c72b716da31a431' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_ip_lists') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 451 requires the exact verified 450 release head' USING ERRCODE='P4510';
    END IF;
END;
$migration_451_up$;

-- 451 (r136 ge36-waf W2; placeholder number, renumbered on merge). Named IP
-- lists a WAF / ACL rule condition "client_ip in_ip_list <id>" references.
-- A tenant list belongs to its tenant scope; a platform list (owned by the
-- platform scope) may be referenced by every tenant. Publication expands the
-- list's current entries into the rule (edgeconfig.WAFIPList); a list change
-- advances revision and republishes every tenant scope whose bound policy
-- references it (system trigger ip_list).
CREATE TABLE security_ip_lists (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 512 AND description !~ '[[:cntrl:]]'),
    entries text[] NOT NULL CHECK (cardinality(entries) BETWEEN 1 AND 10000),
    revision bigint NOT NULL CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    deleted_at timestamptz CHECK (deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at >= created_at))
);
CREATE UNIQUE INDEX security_ip_lists_owner_name_key ON security_ip_lists(owner_scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX security_ip_lists_owner_idx ON security_ip_lists(owner_scope_id, updated_at DESC) WHERE deleted_at IS NULL;
REVOKE ALL ON security_ip_lists FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_ip_lists TO cdnca_control_app, cdnca_control_runtime;

-- Idempotent writes (Idempotency-Key): the request digest and the result.
CREATE TABLE security_ip_list_write_requests (
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    list_id uuid NOT NULL REFERENCES security_ip_lists(id) ON DELETE RESTRICT,
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_scope_id, actor_user_id, idempotency_key)
);
REVOKE ALL ON security_ip_list_write_requests FROM PUBLIC;
GRANT SELECT, INSERT ON security_ip_list_write_requests TO cdnca_control_app, cdnca_control_runtime;

-- A list change republishes the scopes referencing it through the system
-- channel (trigger ip_list; 431's checks extended, cardinality 16 -> 17).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 17 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 17);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list'));
