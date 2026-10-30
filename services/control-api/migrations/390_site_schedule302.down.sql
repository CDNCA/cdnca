LOCK TABLE schema_migrations, sites, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_390_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 390 OR
       (SELECT max(version) FROM schema_migrations) <> 390 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=390 AND
        migration_id='390_site_schedule302' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 390 down requires the exact verified migration head' USING ERRCODE='P3901';
    END IF;
END;
$migration_390_down$;

-- Sites stop being HTTP 302 scheduled on their next release.
DROP TABLE node_schedule302_tables;
DROP INDEX nodes_schedule302_hostname_390_idx;
ALTER TABLE nodes DROP CONSTRAINT nodes_schedule302_hostname_390_check;
UPDATE nodes SET management_settings = management_settings - 'schedule302_hostname'
    WHERE management_settings ? 'schedule302_hostname';
DROP TABLE site_schedule302_write_requests;
DROP TABLE site_schedule302_settings;
