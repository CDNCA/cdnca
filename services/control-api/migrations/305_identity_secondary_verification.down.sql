LOCK TABLE schema_migrations, identity_user_secondary_verification, identity_write_requests,
    notification_event_policies, notification_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_305_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 305 OR
       (SELECT max(version) FROM schema_migrations) <> 305 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=305 AND
        migration_id='305_identity_secondary_verification' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 305 down requires the exact verified migration head' USING ERRCODE='P3051';
    END IF;
    IF EXISTS (SELECT 1 FROM identity_user_secondary_verification) OR
       EXISTS (SELECT 1 FROM identity_write_requests WHERE operation='identity.user.secondary_verification.update') OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='identity_secondary_verification') THEN
        RAISE EXCEPTION 'migration 305 rollback would discard secondary verification requests; preserve them and deploy a compatible binary'
            USING ERRCODE='P3051';
    END IF;
END;
$migration_305_down$;

-- notification_templates rows are immutable facts; they stay and a re-applied up reuses them.
UPDATE notification_event_policies SET supported=false, enabled=false, sms_enabled=false, email_enabled=false, updated_at=now()
WHERE event_type='identity.secondary_verification';

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create','identity.user.update','identity.self.update','identity.membership.suspend',
        'identity.user.password.reset','identity.user.delete','identity.user.login_security.update'
    ));

DROP TABLE identity_user_secondary_verification;
