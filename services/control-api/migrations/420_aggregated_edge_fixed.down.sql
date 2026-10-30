LOCK TABLE schema_migrations, aggregated_edge_site_schedules, aggregated_edge_line_targets,
    aggregated_edge_switch_events, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_420_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 420 OR
       (SELECT max(version) FROM schema_migrations) <> 420 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=420 AND
        migration_id='420_aggregated_edge_fixed' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 420 down requires the exact verified migration head' USING ERRCODE='P4201';
    END IF;
    -- A fixed site would silently start failing over, and its alert history
    -- would be lost: refuse instead.
    IF EXISTS (SELECT 1 FROM aggregated_edge_site_schedules WHERE strategy = 'fixed') OR
       EXISTS (SELECT 1 FROM aggregated_edge_line_targets
               WHERE alert IN ('current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy')) OR
       EXISTS (SELECT 1 FROM aggregated_edge_switch_events
               WHERE reason IN ('current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy')) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'aggregated_edge.schedule.alert.zh-cn') THEN
        RAISE EXCEPTION 'migration 420 rollback would drop fixed scheduling state' USING ERRCODE='P4202';
    END IF;
END;
$migration_420_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'aggregated_edge.schedule.alert.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'aggregated_edge.schedule.alert';
DELETE FROM notification_event_policies WHERE event_type = 'aggregated_edge.schedule.alert';
ALTER TABLE aggregated_edge_line_targets DROP COLUMN alert_kept;
ALTER TABLE aggregated_edge_site_schedules DROP COLUMN freeze_kept;

ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_420_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_394_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'recovered'));
ALTER TABLE aggregated_edge_line_targets DROP CONSTRAINT aggregated_edge_line_targets_alert_420_check;
ALTER TABLE aggregated_edge_line_targets ADD CONSTRAINT aggregated_edge_line_targets_alert_check
    CHECK (alert IN ('', 'all_unhealthy'));
ALTER TABLE aggregated_edge_site_schedules DROP CONSTRAINT aggregated_edge_site_schedules_strategy_420_check;
ALTER TABLE aggregated_edge_site_schedules ADD CONSTRAINT aggregated_edge_site_schedules_strategy_check
    CHECK (strategy IN ('failover', 'quality'));
