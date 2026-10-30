LOCK TABLE schema_migrations, node_monitoring_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_268_up_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 267 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 267 OR
       NOT EXISTS (
        SELECT 1
        FROM schema_migrations
        WHERE version = 267 AND migration_id = '267_node_monitoring_command_outbox_privileges' AND
              checksum_sha256 = 'd8a28a89eeeb4fad2028b1a8f3749f5fbb7e83eaede1bbe61df70f2cc295d533' AND
              down_checksum_sha256 = '034a3eecf93e1416e64919d9065882eb41944b68e377f3ee72e30509469f7a31' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure('protect_node_monitoring_command_outbox()') IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        JOIN pg_proc procedure ON procedure.oid = trigger.tgfoid
        WHERE trigger.tgrelid = 'node_monitoring_command_outbox'::regclass AND
              trigger.tgname = 'node_monitoring_command_outbox_append_only' AND
              NOT trigger.tgisinternal AND procedure.proname = 'protect_node_monitoring_command_outbox'
       ) THEN
        RAISE EXCEPTION 'migration 268 requires the exact verified 267 release head and node monitoring outbox trigger'
            USING ERRCODE = 'P2680';
    END IF;
END;
$migration_268_up_head$;

CREATE OR REPLACE FUNCTION protect_node_monitoring_command_outbox()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node monitoring command outbox facts are append-only';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id,NEW.event_id,NEW.node_id,NEW.config_revision,NEW.subject,NEW.message_id,
               NEW.payload,NEW.payload_sha256,NEW.created_at) IS DISTINCT FROM
           ROW(OLD.id,OLD.event_id,OLD.node_id,OLD.config_revision,OLD.subject,OLD.message_id,
               OLD.payload,OLD.payload_sha256,OLD.created_at) THEN
            RAISE EXCEPTION 'node monitoring command outbox identity is immutable';
        END IF;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.attempt_count <> 0 OR NEW.claim_token IS NOT NULL OR
           NEW.claimed_until IS NOT NULL OR NEW.puback_stream IS NOT NULL OR NEW.puback_sequence IS NOT NULL OR
           NEW.published_at IS NOT NULL OR NEW.last_error_code IS NOT NULL OR NEW.next_attempt_at IS DISTINCT FROM NEW.created_at OR
           NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'invalid initial node monitoring command outbox state';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state IN ('pending','publishing') AND NEW.state = 'publishing' THEN
        IF NEW.claim_token IS NULL OR NEW.claimed_until <= NEW.updated_at OR NEW.attempt_count <> OLD.attempt_count + 1 OR
           NEW.puback_stream IS NOT NULL OR NEW.puback_sequence IS NOT NULL OR NEW.published_at IS NOT NULL OR
           NEW.last_error_code IS NOT NULL THEN
            RAISE EXCEPTION 'invalid node monitoring command outbox claim';
        END IF;
    ELSIF OLD.state = 'publishing' AND NEW.state = 'published' THEN
        IF NEW.claim_token IS NOT NULL OR NEW.claimed_until IS NOT NULL OR NEW.puback_stream <> 'NODE_MONITORING_COMMANDS' OR
           NEW.puback_sequence IS NULL OR NEW.published_at IS NULL OR NEW.last_error_code IS NOT NULL OR
           NEW.attempt_count <> OLD.attempt_count THEN
            RAISE EXCEPTION 'invalid node monitoring command outbox publication';
        END IF;
    ELSIF OLD.state = 'publishing' AND NEW.state = 'pending' THEN
        IF NEW.claim_token IS NOT NULL OR NEW.claimed_until IS NOT NULL OR NEW.published_at IS NOT NULL OR
           NEW.puback_stream IS NOT NULL OR NEW.puback_sequence IS NOT NULL OR NEW.last_error_code IS NULL OR
           NEW.attempt_count <> OLD.attempt_count OR NEW.next_attempt_at < NEW.updated_at THEN
            RAISE EXCEPTION 'invalid node monitoring command outbox retry settlement';
        END IF;
    ELSIF OLD.state = 'publishing' AND NEW.state = 'failed' THEN
        IF NEW.claim_token IS NOT NULL OR NEW.claimed_until IS NOT NULL OR NEW.published_at IS NOT NULL OR
           NEW.puback_stream IS NOT NULL OR NEW.puback_sequence IS NOT NULL OR NEW.last_error_code IS NULL OR
           NEW.attempt_count <> OLD.attempt_count THEN
            RAISE EXCEPTION 'invalid node monitoring command outbox failure settlement';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid node monitoring command outbox state transition';
    END IF;
    RETURN NEW;
END;
$$;
