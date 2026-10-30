LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_385_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 385 OR
       (SELECT max(version) FROM schema_migrations) <> 385 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=385 AND
        migration_id='385_site_traffic_limits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 385 down requires the exact verified migration head' USING ERRCODE='P3851';
    END IF;
END;
$migration_385_down$;

-- Exceeded sites serve again on their next release.
DROP TABLE site_traffic_limit_write_requests;
DROP TABLE site_traffic_limits;
