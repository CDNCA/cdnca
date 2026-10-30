LOCK TABLE schema_migrations,control_installation_entitlement,
    control_upgrade_systemd_repository_154 IN ACCESS EXCLUSIVE MODE;

DO $migration_154$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>154 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>154 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=154 AND migration_id='154_control_upgrade_systemd_repository' AND
              checksum_sha256='b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=153 AND migration_id='153_node_revocation_checkpoint' AND
              checksum_sha256='625a59e7f6be7ebe73877550e87ac230f7fb118aeb8e69243553fe16574d1fbf' AND
              down_checksum_sha256='837e31ebeb2aa9cb3cf11e3bf58666f50b01fa7eefa29e5cfd8e80a05ec2c87b' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 154 rollback requires the exact verified 154 head'
            USING ERRCODE='P1540';
    END IF;
    IF EXISTS(SELECT 1 FROM control_upgrade_systemd_repository_154) THEN
        RAISE EXCEPTION 'migration 154 rollback would discard durable control upgrade state'
            USING ERRCODE='P1542';
    END IF;
END;
$migration_154$;

DROP TRIGGER control_upgrade_systemd_repository_truncate_154 ON control_upgrade_systemd_repository_154;
DROP TRIGGER control_upgrade_systemd_repository_guard_154 ON control_upgrade_systemd_repository_154;
DROP FUNCTION prevent_control_upgrade_systemd_repository_truncate_154();
DROP FUNCTION guard_control_upgrade_systemd_repository_154();
DROP TABLE control_upgrade_systemd_repository_154;
