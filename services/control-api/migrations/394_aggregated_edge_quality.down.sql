LOCK TABLE schema_migrations, aggregated_edge_site_schedules, aggregated_edge_probe_rounds,
    aggregated_edge_switch_events IN ACCESS EXCLUSIVE MODE;

DO $migration_394_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 394 OR
       (SELECT max(version) FROM schema_migrations) <> 394 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=394 AND
        migration_id='394_aggregated_edge_quality' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 394 down requires the exact verified migration head' USING ERRCODE='P3941';
    END IF;
    -- Quality switches are switching history (the audit trail of DNS
    -- changes); the older reason CHECK cannot hold them.
    IF EXISTS (SELECT 1 FROM aggregated_edge_switch_events WHERE reason = 'quality') THEN
        RAISE EXCEPTION 'migration 394 rollback would drop quality switch history' USING ERRCODE='P3942';
    END IF;
END;
$migration_394_down$;

DROP INDEX aggregated_edge_switch_events_window_394_idx;
CREATE INDEX aggregated_edge_switch_events_window_366_idx ON aggregated_edge_switch_events (site_id, created_at)
    WHERE reason IN ('failover', 'failback');
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_394_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_check
    CHECK (reason IN ('failover', 'failback', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'recovered'));
DROP TABLE aggregated_edge_probe_rounds;
ALTER TABLE aggregated_edge_site_schedules
    DROP COLUMN quality_margin,
    DROP COLUMN quality_min_interval_seconds,
    DROP COLUMN strategy;
