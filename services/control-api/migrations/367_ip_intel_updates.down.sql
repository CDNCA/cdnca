LOCK TABLE schema_migrations, artifact_catalog_entries, local_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_367_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 367 OR
       (SELECT max(version) FROM schema_migrations) <> 367 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=367 AND
        migration_id='367_ip_intel_updates' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 367 down requires the exact verified migration head' USING ERRCODE='P3671';
    END IF;
    -- A locally built library may already be on nodes; local artifacts are
    -- never deleted (353 trigger): refuse rather than orphan it.
    IF EXISTS (SELECT 1 FROM artifact_catalog_entries WHERE origin = 'local') THEN
        RAISE EXCEPTION 'migration 367 down refuses to drop a locally built IP intelligence library' USING ERRCODE='P3672';
    END IF;
END;
$migration_367_down$;

DELETE FROM role_permissions WHERE permission_name = 'system.ip_intel_updates.manage';
DELETE FROM permissions WHERE name = 'system.ip_intel_updates.manage';
DROP TABLE ip_intel_update_write_requests;
DROP TABLE ip_intel_update_state;
DROP TABLE ip_intel_update_settings;
ALTER TABLE artifact_catalog_entries
    DROP CONSTRAINT artifact_catalog_entries_origin_367_ck,
    ALTER COLUMN delivery_id SET NOT NULL,
    DROP COLUMN origin;
