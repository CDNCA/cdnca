LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_195$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 194 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 194 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=194 AND migration_id='194_platform_system_user_settings' AND checksum_sha256='9f26f465cecf170606bf5c3a65bd42aca5b0463e61ddfc1a200fe6bfd37cda3b' AND down_checksum_sha256='b2e061e4a430ba356d45fec63af78aeeb71c346f9e9b791d9b9fd06b892e33fb' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 195 requires the exact verified 194 release head' USING ERRCODE='P1950';
    END IF;
END;
$migration_195$;

CREATE TABLE platform_system_mail_settings (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision >= 0 AND revision < 9223372036854775807),
    settings jsonb NOT NULL CHECK (jsonb_typeof(settings)='object'),
    updated_by_user_id uuid,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (platform_scope_id,updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_platform_system_mail_settings_scope_195() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform' AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'platform system mail settings require a platform scope' USING ERRCODE='P1951';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_system_mail_settings_scope_195 BEFORE INSERT OR UPDATE ON platform_system_mail_settings FOR EACH ROW EXECUTE FUNCTION validate_platform_system_mail_settings_scope_195();

CREATE TABLE platform_system_mail_settings_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation='system_mail_settings.update'),
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

CREATE INDEX platform_system_mail_settings_write_requests_scope_created_195 ON platform_system_mail_settings_write_requests(target_scope_id,created_at DESC);
REVOKE ALL ON platform_system_mail_settings,platform_system_mail_settings_write_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_platform_system_mail_settings_scope_195() FROM PUBLIC;
