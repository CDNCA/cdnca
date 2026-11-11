LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_652_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 651 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 651 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=651 AND
        migration_id='651_site_server_timing' AND
        checksum_sha256='983b37fb8e0958e0595f2b96393028d7b002ec42d77124bed4233651ae75f736' AND
        down_checksum_sha256='e82018d4d9b827703426225ac7a6215ff662f7799e486e9447ffe3ea7544840b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_string_sets') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 652 requires the exact verified 651 release head' USING ERRCODE='P6520';
    END IF;
END;
$migration_652_up$;

-- 652. Named string sets a WAF rule condition
-- "<field> in_string_set <id>" references (host, path, request_uri,
-- user_agent, referer, header, ja4). A tenant set belongs to its tenant
-- scope; a platform set (owned by the platform scope) may be referenced by
-- every tenant. Unlike IP lists the members are not inlined into the rules:
-- the site object carries each referenced set once (security.string_sets) at
-- the revision the rules name. match_mode and case_sensitive are fixed at
-- creation (changing them would silently change every referencing rule).
CREATE TABLE security_string_sets (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 512 AND description !~ '[[:cntrl:]]'),
    match_mode text NOT NULL CHECK (match_mode IN ('exact', 'prefix', 'suffix', 'contains', 'wildcard')),
    case_sensitive boolean NOT NULL,
    entries text[] NOT NULL CHECK (cardinality(entries) BETWEEN 1 AND 10000),
    entries_bytes integer NOT NULL CHECK (entries_bytes BETWEEN 1 AND 262144),
    revision bigint NOT NULL CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    deleted_at timestamptz CHECK (deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at >= created_at))
);
CREATE UNIQUE INDEX security_string_sets_owner_name_key ON security_string_sets(owner_scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX security_string_sets_owner_idx ON security_string_sets(owner_scope_id, updated_at DESC) WHERE deleted_at IS NULL;
REVOKE ALL ON security_string_sets FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_string_sets TO cdnca_control_app, cdnca_control_runtime;

CREATE FUNCTION security_string_sets_fixed_mode() RETURNS trigger LANGUAGE plpgsql AS $fixed$
BEGIN
    IF NEW.match_mode IS DISTINCT FROM OLD.match_mode OR NEW.case_sensitive IS DISTINCT FROM OLD.case_sensitive OR
       NEW.owner_scope_id IS DISTINCT FROM OLD.owner_scope_id THEN
        RAISE EXCEPTION 'security string set match mode, case sensitivity and owner are fixed' USING ERRCODE='P6521';
    END IF;
    RETURN NEW;
END;
$fixed$;
CREATE TRIGGER security_string_sets_fixed_mode BEFORE UPDATE ON security_string_sets
    FOR EACH ROW EXECUTE FUNCTION security_string_sets_fixed_mode();

-- Every published revision's members, immutable: a publication rebuilt from
-- an earlier compiled document (system republication over a stop overlay)
-- still names the revision it was compiled with.
CREATE TABLE security_string_set_revisions (
    set_id uuid NOT NULL REFERENCES security_string_sets(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    entries text[] NOT NULL CHECK (cardinality(entries) BETWEEN 1 AND 10000),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (set_id, revision)
);
REVOKE ALL ON security_string_set_revisions FROM PUBLIC;
GRANT SELECT, INSERT ON security_string_set_revisions TO cdnca_control_app, cdnca_control_runtime;

-- Idempotent writes (Idempotency-Key): the request digest and the result.
CREATE TABLE security_string_set_write_requests (
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    set_id uuid NOT NULL REFERENCES security_string_sets(id) ON DELETE RESTRICT,
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_scope_id, actor_user_id, idempotency_key)
);
REVOKE ALL ON security_string_set_write_requests FROM PUBLIC;
GRANT SELECT, INSERT ON security_string_set_write_requests TO cdnca_control_app, cdnca_control_runtime;

-- A set change republishes the scopes referencing it through the system
-- channel (trigger string_set; 598's checks extended, cardinality 23 -> 24).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 24 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension', 'certificate_renewal',
            'security_hold', 'string_set']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 24);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension', 'certificate_renewal', 'security_hold', 'string_set'));
