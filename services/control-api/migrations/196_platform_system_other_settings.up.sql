LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_196$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 195 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 195 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=195 AND migration_id='195_platform_system_mail_settings' AND checksum_sha256='37f666d8f4d51db10b4ea70731ed1cf41b8005318b2d326b09cee1605906fdd0' AND down_checksum_sha256='c042473c80293ae72e05bdbcec5ef64934e327280d44bfc4d7adca52f838fcf8' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 196 requires the exact verified 195 release head' USING ERRCODE='P1960';
    END IF;
END;
$migration_196$;

CREATE TABLE platform_system_other_settings (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision >= 0 AND revision < 9223372036854775807),
    settings jsonb NOT NULL CHECK (jsonb_typeof(settings)='object'),
    updated_by_user_id uuid,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (platform_scope_id,updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_platform_system_other_settings_scope_196() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform' AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'platform system other settings require a platform scope' USING ERRCODE='P1961';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_system_other_settings_scope_196 BEFORE INSERT OR UPDATE ON platform_system_other_settings FOR EACH ROW EXECUTE FUNCTION validate_platform_system_other_settings_scope_196();

CREATE TABLE platform_system_other_settings_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation='system_other_settings.update'),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE(actor_user_id,operation,idempotency_key),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK(actor_scope_id=target_scope_id),
    CHECK((completed_at IS NULL AND response_body IS NULL) OR (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at>=created_at))
);

CREATE INDEX platform_system_other_settings_write_requests_scope_created_196 ON platform_system_other_settings_write_requests(target_scope_id,created_at DESC);
REVOKE ALL ON platform_system_other_settings,platform_system_other_settings_write_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_platform_system_other_settings_scope_196() FROM PUBLIC;
