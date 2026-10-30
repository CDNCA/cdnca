LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_193$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 192 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 192 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=192 AND migration_id='192_platform_system_settings' AND
            checksum_sha256='4eea40966f0c6b5833135d62668250f032bcd4c9d363bd2041de577c7f7a0ab0' AND
            down_checksum_sha256='885084c8e9a5af5b0990f2a86a31761471bddf27ec5ceebf2805350d78f89047' AND
            integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 193 requires the exact verified 192 release head' USING ERRCODE='P1930';
    END IF;
END;
$migration_193$;

CREATE TABLE platform_system_cleanup_settings (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision >= 0 AND revision < 9223372036854775807),
    settings jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object'),
    updated_by_user_id uuid,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (platform_scope_id, updated_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_platform_system_cleanup_settings_scope_193()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform' AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'platform system cleanup settings require a platform scope' USING ERRCODE='P1931';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_system_cleanup_settings_scope_193
BEFORE INSERT OR UPDATE ON platform_system_cleanup_settings
FOR EACH ROW EXECUTE FUNCTION validate_platform_system_cleanup_settings_scope_193();

CREATE TABLE platform_system_cleanup_settings_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation='system_cleanup_settings.update'),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (actor_scope_id=target_scope_id),
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at))
);

CREATE INDEX platform_system_cleanup_settings_write_requests_scope_created_193 ON platform_system_cleanup_settings_write_requests(target_scope_id, created_at DESC);
REVOKE ALL ON platform_system_cleanup_settings, platform_system_cleanup_settings_write_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_platform_system_cleanup_settings_scope_193() FROM PUBLIC;
