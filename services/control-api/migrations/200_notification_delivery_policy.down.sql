LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_200_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 200 OR
       (SELECT max(version) FROM schema_migrations) <> 200 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=200 AND migration_id='200_notification_delivery_policy' AND integrity_state='verified') THEN
        RAISE EXCEPTION 'migration 200 rollback requires the verified 200 head' USING ERRCODE='P2000';
    END IF;
END;
$migration_200_down$;

DO $revoke_notification_policy$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        REVOKE SELECT,INSERT,UPDATE ON notification_delivery_policy, notification_event_policies FROM cdnca_control_app;
    END IF;
END;
$revoke_notification_policy$;

DROP TABLE notification_event_policies;
DROP TABLE notification_delivery_policy;
