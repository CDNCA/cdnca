-- Requires the exact verified certificate defaults schema from migration 258.
DO $migration_259_up_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 258 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 258 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 258 AND migration_id = '258_certificate_user_defaults' AND
              checksum_sha256 = '092b366bc037c7d81c4ab24fbff6d54302b7a4cd350193dc0237ba86f365eb92' AND
              down_checksum_sha256 = 'ab91ac6664a5d817a86fb937993880ace5043fdf872e065899a3b1b1f188d584' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 259 requires the exact verified 258 release head'
            USING ERRCODE = 'P2590';
    END IF;
END;
$migration_259_up_head$;

-- Do not erase grants that predate this migration. Such overlap requires review.
DO $migration_259_runtime_grants$
DECLARE
    runtime_role oid := to_regrole('cdnca_control_app');
BEGIN
    IF runtime_role IS NULL THEN
        RAISE EXCEPTION 'migration 259 requires the provisioned cdnca_control_app role'
            USING ERRCODE = '42704';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_class relation
        CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) acl
        WHERE relation.oid IN ('certificate_user_defaults'::regclass, 'certificate_default_write_requests'::regclass)
          AND acl.grantee = runtime_role
          AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE')
    ) THEN
        RAISE EXCEPTION 'migration 259 requires review of existing cdnca_control_app certificate defaults grants'
            USING ERRCODE = 'P2591';
    END IF;
END;
$migration_259_runtime_grants$;

GRANT SELECT, INSERT, UPDATE ON certificate_user_defaults TO cdnca_control_app;
GRANT SELECT, INSERT, UPDATE ON certificate_default_write_requests TO cdnca_control_app;
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
