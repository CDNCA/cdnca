LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_428_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 428 OR
       (SELECT max(version) FROM schema_migrations) <> 428 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=428 AND
        migration_id='428_dnspup_probe' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 428 down requires the exact verified migration head' USING ERRCODE='P4281';
    END IF;
    -- Sent alerts reference the template: refuse rather than orphan them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'probe.dnspup.degraded.zh-cn') THEN
        RAISE EXCEPTION 'migration 428 rollback would drop sent dnspup probe alerts' USING ERRCODE='P4282';
    END IF;
END;
$migration_428_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'probe.dnspup.degraded.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'probe.dnspup.degraded';
DELETE FROM notification_event_policies WHERE event_type = 'probe.dnspup.degraded';
DELETE FROM role_permissions WHERE permission_name = 'system.probe_dnspup.manage';
DELETE FROM permissions WHERE name = 'system.probe_dnspup.manage';
DROP TABLE probe_dnspup_write_requests;
DROP TABLE probe_dnspup_state;
DROP TABLE probe_dnspup_settings;
