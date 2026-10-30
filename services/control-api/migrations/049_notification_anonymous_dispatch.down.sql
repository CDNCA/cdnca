LOCK TABLE notification_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM notification_events
        WHERE recipient_kind <> 'member'
           OR recipient_user_id IS NULL
           OR anonymous_dispatch_reference IS NOT NULL
           OR event_type = 'identity.account_recovery'
    ) THEN
        RAISE EXCEPTION 'cannot roll back anonymous notification dispatch while anonymous facts exist'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP INDEX notification_events_anonymous_reference_049;
DROP INDEX notification_events_anonymous_source_049;

ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_recipient_one_of_049,
    ALTER COLUMN recipient_user_id SET NOT NULL,
    DROP COLUMN anonymous_dispatch_reference,
    DROP COLUMN recipient_kind;
