LOCK TABLE schema_migrations, notification_delivery_command_receipts_108,
    notification_delivery_facts_108, notification_delivery_settlements_108,
    notification_outbox, notification_attempts, audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    RAISE EXCEPTION 'migration 108 rollback requires the exact verified 108 head; release checksum is not frozen'
        USING ERRCODE='P1080';
END;
$$;

DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM notification_delivery_facts_108) OR
       EXISTS(SELECT 1 FROM notification_delivery_command_receipts_108) OR
       EXISTS(SELECT 1 FROM notification_outbox WHERE generation<>1 OR replay_of_outbox_id IS NOT NULL OR status IN ('accepted','unknown','cancelled')) THEN
        RAISE EXCEPTION 'migration 108 rollback would discard notification settlement facts'
            USING ERRCODE='P1081';
    END IF;
END;
$$;

DROP TRIGGER notification_outbox_transition_108 ON notification_outbox;
DROP FUNCTION guard_notification_outbox_transition_108();
DROP INDEX audit_events_notification_delivery_command_108;
DROP TABLE notification_delivery_command_receipts_108;
DROP TABLE notification_delivery_facts_108;
DROP TABLE notification_delivery_settlements_108;

ALTER TABLE notification_attempts
    DROP CONSTRAINT notification_attempts_shape_108,
    DROP CONSTRAINT notification_attempts_outcome_check,
    ADD CONSTRAINT notification_attempts_outcome_check CHECK (
        outcome IN ('leased','succeeded','temporary_failure','permanent_failure','exhausted','lease_expired')
    ),
    ADD CONSTRAINT notification_attempts_check CHECK (
        (outcome='leased' AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NULL) OR
        (outcome='succeeded' AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL) OR
        (outcome='temporary_failure' AND failure_code IS NOT NULL AND next_attempt_at IS NOT NULL AND completed_at IS NOT NULL) OR
        (outcome IN ('permanent_failure','exhausted','lease_expired') AND failure_code IS NOT NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL)
    );

ALTER TABLE notification_outbox
    DROP CONSTRAINT notification_outbox_replay_source_108_fk,
    DROP CONSTRAINT notification_outbox_replay_generation_108_check,
    DROP CONSTRAINT notification_outbox_event_channel_generation_108_key,
    DROP CONSTRAINT notification_outbox_failure_shape_108,
    DROP CONSTRAINT notification_outbox_state_shape_108,
    DROP CONSTRAINT notification_outbox_status_check,
    DROP CONSTRAINT notification_outbox_dedup_key_check,
    DROP COLUMN replay_of_outbox_id,
    DROP COLUMN generation,
    ADD CONSTRAINT notification_outbox_dedup_key_check CHECK (dedup_key ~ '^notification-v1-[0-9a-f]{64}$'),
    ADD CONSTRAINT notification_outbox_status_check CHECK (status IN ('pending','leased','succeeded','permanent_failed','exhausted')),
    ADD CONSTRAINT notification_outbox_event_id_channel_key UNIQUE(event_id,channel),
    ADD CONSTRAINT notification_outbox_check CHECK (
        (status='pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status='leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('succeeded','permanent_failed','exhausted') AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    ADD CONSTRAINT notification_outbox_check1 CHECK (
        (status='succeeded' AND last_failure_code IS NULL) OR
        (status IN ('permanent_failed','exhausted') AND last_failure_code IS NOT NULL) OR
        status IN ('pending','leased')
    );

CREATE OR REPLACE FUNCTION protect_notification_outbox_payload()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('succeeded','permanent_failed','exhausted') THEN
        RAISE EXCEPTION 'completed notification outbox is immutable';
    END IF;
    IF ROW(NEW.id,NEW.scope_id,NEW.event_id,NEW.channel,NEW.template_id,
           NEW.template_version,NEW.subject,NEW.body,NEW.dedup_key,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.scope_id,OLD.event_id,OLD.channel,OLD.template_id,
           OLD.template_version,OLD.subject,OLD.body,OLD.dedup_key,OLD.created_at) THEN
        RAISE EXCEPTION 'notification outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$$;
