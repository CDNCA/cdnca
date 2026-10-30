LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_355_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 354 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 354 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=354 AND
        migration_id='354_edge_site_objects' AND
        checksum_sha256='06b5e447a616e274de5bbe543c912dbe19d59b95ce029e6aba73cab40ae42ff4' AND
        down_checksum_sha256='d4c3c472ce1bd27ecd9e8c20c3ce7c946a080898e004c64326dc0521e7e1c4c1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_quick_block_overrides') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 355 requires the exact verified 354 release head' USING ERRCODE='P3550';
    END IF;
END;
$migration_355_up$;

-- r136 quickblock-site (placeholder number; renumbered on merge): a site's
-- own quick block settings (securitypolicy.QuickBlockOverride). Each item
-- is null (inherit the site's WAF rule library), or the site's value; a site
-- without a row inherits everything. The site's v2 release compiles the
-- library's quick block with the override applied
-- (edgepublish bindSoldPackageRuntimeSecurity); a write advances
-- sites.revision (the GET/PUT If-Match), which publishes the site as every
-- site setting does.
CREATE TABLE site_quick_block_overrides (
    scope_id uuid NOT NULL,
    site_id uuid PRIMARY KEY,
    override jsonb NOT NULL CHECK (jsonb_typeof(override) = 'object' AND override <> '{}'::jsonb),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE INDEX site_quick_block_overrides_scope_idx ON site_quick_block_overrides (scope_id);

CREATE TABLE site_quick_block_write_requests (
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

CREATE INDEX site_quick_block_write_requests_scope_created_idx
    ON site_quick_block_write_requests (target_scope_id, created_at DESC);
