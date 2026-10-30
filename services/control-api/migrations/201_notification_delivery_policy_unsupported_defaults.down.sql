LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_201_down$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=201 AND migration_id='201_notification_delivery_policy_unsupported_defaults' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 201 rollback requires a verified 201 release head' USING ERRCODE='P2002';
    END IF;
END;
$migration_201_down$;

UPDATE notification_event_policies
SET enabled=true, sms_enabled=true, email_enabled=true, updated_at=now()
WHERE supported=false;
