LOCK TABLE schema_migrations, notification_events, notification_templates, tenant_member_invitations_398 IN ACCESS EXCLUSIVE MODE;

DO $migration_398_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 398 OR
       (SELECT max(version) FROM schema_migrations) <> 398 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=398 AND
        migration_id='398_tenant_member_invitations' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 398 down requires the exact verified migration head' USING ERRCODE='P3982';
    END IF;
    -- Invitations and their mails are history; the older event CHECK cannot hold them.
    IF EXISTS (SELECT 1 FROM tenant_member_invitations_398) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='identity.tenant_member_invitation') THEN
        RAISE EXCEPTION 'migration 398 rollback would drop tenant member invitation history' USING ERRCODE='P3983';
    END IF;
END;
$migration_398_down$;

DROP TABLE tenant_member_invitations_398;
DROP FUNCTION guard_tenant_member_invitations_398();
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='tenant_member_invitation' AND version=1 AND channel='email';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_recipient_one_of_049,
    ADD CONSTRAINT notification_events_recipient_one_of_049 CHECK (
        (
            recipient_kind = 'member' AND
            recipient_user_id IS NOT NULL AND
            anonymous_dispatch_reference IS NULL AND
            event_type <> 'identity.account_recovery'
        ) OR (
            recipient_kind = 'anonymous' AND
            recipient_user_id IS NULL AND
            anonymous_dispatch_reference IS NOT NULL AND
            anonymous_dispatch_reference <> '00000000-0000-0000-0000-000000000000'::uuid AND
            event_type IN (
                'identity.account_recovery',
                'identity.account_registration_verification',
                'identity.account_login_verification'
            ) AND
            delivery_policy = 'system_required'
        )
    );
