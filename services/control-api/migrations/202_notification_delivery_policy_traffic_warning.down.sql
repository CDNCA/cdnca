LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_202_down$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=202 AND migration_id='202_notification_delivery_policy_traffic_warning' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 202 rollback requires a verified 202 release head' USING ERRCODE='P2021';
    END IF;
END;
$migration_202_down$;

DELETE FROM notification_event_policies
WHERE event_type = 'package.monitor.traffic.warning';

