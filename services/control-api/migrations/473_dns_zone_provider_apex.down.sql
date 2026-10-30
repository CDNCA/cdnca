LOCK TABLE schema_migrations, dns_zones IN ACCESS EXCLUSIVE MODE;

DO $migration_473_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 473 OR
       (SELECT max(version) FROM schema_migrations) <> 473 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=473 AND
        migration_id='473_dns_zone_provider_apex' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 473 down requires the exact verified migration head' USING ERRCODE='P4731';
    END IF;
END;
$migration_473_down$;

-- Provider calls fall back to the zone name as the hosted domain.
ALTER TABLE dns_zones
    DROP COLUMN provider_zone_apex;
