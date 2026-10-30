LOCK TABLE schema_migrations, package_subscription_auto_renew_settings, package_auto_renew_attempts,
    notification_templates, notification_event_policies, notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_308_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 308 OR
       (SELECT max(version) FROM schema_migrations) <> 308 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=308 AND
        migration_id='308_package_auto_renew' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 308 down requires the exact verified migration head' USING ERRCODE='P3081';
    END IF;
    -- Rolling back must not silently drop a customer's switch or the record
    -- of money already taken.
    IF EXISTS (SELECT 1 FROM package_subscription_auto_renew_settings WHERE enabled) OR
       EXISTS (SELECT 1 FROM package_auto_renew_attempts) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type LIKE 'package.auto_renew.%') THEN
        RAISE EXCEPTION 'package auto-renew facts prevent rollback' USING ERRCODE='P3082';
    END IF;
END;
$migration_308_down$;

DELETE FROM notification_event_policies
WHERE event_type IN ('package.auto_renew.succeeded', 'package.auto_renew.failed');
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates
WHERE version = 1 AND template_id IN ('package.auto_renew.succeeded.zh-cn', 'package.auto_renew.failed.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

DROP TABLE package_auto_renew_attempts;
DROP FUNCTION prevent_package_auto_renew_attempt_mutation_308();
DROP TABLE package_subscription_auto_renew_settings;
