DO $migration_259_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 259 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 259 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 259 AND migration_id = '259_certificate_defaults_runtime_grants' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 258 AND migration_id = '258_certificate_user_defaults' AND
              checksum_sha256 = '092b366bc037c7d81c4ab24fbff6d54302b7a4cd350193dc0237ba86f365eb92' AND
              down_checksum_sha256 = 'ab91ac6664a5d817a86fb937993880ace5043fdf872e065899a3b1b1f188d584' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 259 rollback requires the exact verified 259 release head'
            USING ERRCODE = 'P2592';
    END IF;
END;
$migration_259_down$;

REVOKE SELECT, INSERT, UPDATE ON certificate_user_defaults FROM cdnca_control_app RESTRICT;
REVOKE SELECT, INSERT, UPDATE ON certificate_default_write_requests FROM cdnca_control_app RESTRICT;
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
