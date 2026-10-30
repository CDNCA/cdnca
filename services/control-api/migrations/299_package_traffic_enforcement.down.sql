LOCK TABLE schema_migrations, package_traffic_site_suspensions, package_traffic_enforcement_schedule,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_299_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 299 OR
       (SELECT max(version) FROM schema_migrations) <> 299 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=299 AND
        migration_id='299_package_traffic_enforcement' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 299 down requires the exact verified migration head' USING ERRCODE='P2992';
    END IF;
    -- An open suspension is the only record that lets a stopped site resume.
    IF EXISTS (SELECT 1 FROM package_traffic_site_suspensions WHERE recovered_at IS NULL) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
               ('package.traffic.suspended.zh-cn', 'package.traffic.recovered.zh-cn')) THEN
        RAISE EXCEPTION 'migration 299 rollback would strand traffic-suspended sites or sent notifications'
            USING ERRCODE='P2992';
    END IF;
END;
$migration_299_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates
WHERE template_id IN ('package.traffic.suspended.zh-cn', 'package.traffic.recovered.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DROP TABLE package_traffic_enforcement_schedule;
DROP TRIGGER package_traffic_site_suspensions_close_once_299 ON package_traffic_site_suspensions;
DROP TABLE package_traffic_site_suspensions;
DROP FUNCTION protect_package_traffic_site_suspension_299();
