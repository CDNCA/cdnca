LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_206$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=205
          AND migration_id='205_cc_references'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 206 requires a verified 205 CC references head' USING ERRCODE='P2060';
    END IF;
END;
$migration_206$;

CREATE TABLE dns_legacy_settings (
    scope_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    ttl integer NOT NULL DEFAULT 600 CHECK (ttl BETWEEN 1 AND 604800),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, tenant_id) REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, updated_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE dns_legacy_settings_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation='dns.legacy_settings.update'),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response_body jsonb,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE(actor_user_id, operation, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_scope_id) REFERENCES access_scopes(id) ON DELETE RESTRICT,
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND response_body IS NOT NULL))
);

CREATE INDEX dns_legacy_settings_write_requests_scope_created_idx
    ON dns_legacy_settings_write_requests(target_scope_id, created_at DESC);

REVOKE ALL ON dns_legacy_settings, dns_legacy_settings_write_requests FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cdnca_control_app;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON TABLE dns_legacy_settings, dns_legacy_settings_write_requests
    TO cdnca_control_app;
