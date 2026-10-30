LOCK TABLE schema_migrations, site_supply_bindings, site_supply_cdn_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_366_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 366 OR
       (SELECT max(version) FROM schema_migrations) <> 366 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=366 AND
        migration_id='366_aggregated_edge_schedule' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 366 down requires the exact verified migration head' USING ERRCODE='P3661';
    END IF;
END;
$migration_366_down$;

ALTER TABLE site_supply_cdn_sites DROP COLUMN drained_at;
DROP TABLE aggregated_edge_switch_events;
DROP TABLE aggregated_edge_target_health;
DROP TABLE aggregated_edge_line_targets;
DROP TABLE aggregated_edge_site_schedules;
ALTER TABLE site_supply_bindings DROP CONSTRAINT site_supply_bindings_line_scope_366_check;
