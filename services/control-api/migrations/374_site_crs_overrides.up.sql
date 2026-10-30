LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_374_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 373 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 373 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=373 AND
        migration_id='373_theme_tenant_whitelabel' AND
        checksum_sha256='bb6678b98976f84ec4c18697bd2cee84f75a604d6809359c7f5731c251c529e7' AND
        down_checksum_sha256='d20e3f4d63eb38883d389ee4061746c5846a66a9ee2e30854a679cb1639398a3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_crs_overrides') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 374 requires the exact verified 373 release head' USING ERRCODE='P3740';
    END IF;
END;
$migration_374_up$;

-- r136 PA-12 (placeholder number; renumbered on merge): a site's own OWASP
-- CRS settings (securitypolicy.CRSOverride). profile is null (inherit the
-- site's WAF rule library) or a CRS profile pack ID (system/crs-<level>);
-- exclusions null (inherit) or the scoring rule IDs the site does not
-- evaluate (from that profile's exports). A site without a row inherits
-- both. A write advances sites.revision (GET ETag / PUT If-Match), which
-- publishes the site as every site setting does.
CREATE TABLE site_crs_overrides (
    scope_id uuid NOT NULL,
    site_id uuid PRIMARY KEY,
    override jsonb NOT NULL CHECK (jsonb_typeof(override) = 'object' AND override <> '{}'::jsonb AND
        (override->'profile' IS NULL OR jsonb_typeof(override->'profile') IN ('string', 'null')) AND
        (override->'exclusions' IS NULL OR jsonb_typeof(override->'exclusions') IN ('array', 'null'))),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE INDEX site_crs_overrides_scope_idx ON site_crs_overrides (scope_id);

CREATE TABLE site_crs_write_requests (
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

CREATE INDEX site_crs_write_requests_scope_created_idx
    ON site_crs_write_requests (target_scope_id, created_at DESC);
