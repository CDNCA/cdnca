LOCK TABLE notification_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM notification_events
        WHERE event_type = 'identity.account_recovery'
    ) THEN
        RAISE EXCEPTION 'cannot classify pre-existing account recovery notification facts'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

ALTER TABLE notification_events
    ADD COLUMN recipient_kind text NOT NULL DEFAULT 'member',
    ADD COLUMN anonymous_dispatch_reference uuid,
    ALTER COLUMN recipient_user_id DROP NOT NULL,
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
            event_type = 'identity.account_recovery' AND
            delivery_policy = 'system_required'
        )
    );

CREATE UNIQUE INDEX notification_events_anonymous_source_049
    ON notification_events (scope_id, source_event_id, event_type)
    WHERE recipient_kind = 'anonymous';

CREATE UNIQUE INDEX notification_events_anonymous_reference_049
    ON notification_events (anonymous_dispatch_reference)
    WHERE recipient_kind = 'anonymous';
