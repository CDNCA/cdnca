-- 666 回退：删掉本迁移重建的成员邀请/重置结果库对象（回到 527 的状态）。
LOCK TABLE schema_migrations, notification_events, notification_templates, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_666_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 666 OR
       (SELECT max(version) FROM schema_migrations) <> 666 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=666 AND migration_id='666_tenant_members_restore' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 666 down requires the exact verified migration head' USING ERRCODE='P6661';
    END IF;
    IF EXISTS (SELECT 1 FROM tenant_member_invitations_398) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='identity.tenant_member_invitation') OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='tenant_member_invitation') THEN
        RAISE EXCEPTION 'migration 666 rollback found tenant member invitation history' USING ERRCODE='P6663';
    END IF;
END;
$migration_666_down$;

DROP TABLE tenant_member_invitations_398;
DROP FUNCTION guard_tenant_member_invitations_398();
DROP TABLE tenant_member_password_reset_results;
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

CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        RAISE EXCEPTION 'certificate asset owner is immutable' USING ERRCODE='P2761';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app;
