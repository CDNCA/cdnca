LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_266_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 265 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 265 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 265 AND migration_id = '265_node_metrics_telemetry' AND
              checksum_sha256 = 'ee7910398295e0d7d60f34b39e9f41853f6b78de4e4eeebc0bdfcac61d860767' AND
              down_checksum_sha256 = '1b65d4456d9becb6a86536e3f0882a4b30af340f096e4975081c0c09110c8e3c' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 266 requires the exact verified 265 release head'
            USING ERRCODE = 'P2660';
    END IF;
END;
$migration_266_up$;

CREATE TABLE node_monitoring_command_outbox (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    event_id uuid NOT NULL UNIQUE CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    node_id uuid NOT NULL CHECK (node_id <> '00000000-0000-0000-0000-000000000000'::uuid) REFERENCES nodes(id) ON DELETE RESTRICT,
    config_revision bigint NOT NULL CHECK (config_revision > 0),
    subject text NOT NULL CHECK (subject = 'cdnca.agent.node-monitoring.commands.' || node_id::text),
    message_id text NOT NULL UNIQUE CHECK (message_id = 'node-monitoring-v1-' || event_id::text),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','publishing','published','failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 16),
    next_attempt_at timestamptz NOT NULL,
    claim_token uuid,
    claimed_until timestamptz,
    puback_stream text,
    puback_sequence bigint CHECK (puback_sequence IS NULL OR puback_sequence > 0),
    published_at timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code = btrim(last_error_code) AND char_length(last_error_code) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (node_id, config_revision),
    CHECK ((claim_token IS NULL) = (claimed_until IS NULL)),
    CHECK (claim_token IS NULL OR claim_token <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK ((state = 'publishing') = (claim_token IS NOT NULL AND claimed_until IS NOT NULL)),
    CHECK (state <> 'publishing' OR claimed_until > updated_at),
    CHECK ((puback_stream IS NULL) = (puback_sequence IS NULL)),
    CHECK ((state = 'published') = (published_at IS NOT NULL AND puback_stream IS NOT NULL AND puback_sequence IS NOT NULL)),
    CHECK (published_at IS NULL OR state = 'published'),
    CHECK (state <> 'failed' OR last_error_code IS NOT NULL),
    CHECK (state IN ('pending','publishing') OR published_at IS NULL OR published_at >= created_at)
);

CREATE INDEX node_monitoring_command_outbox_ready_idx
    ON node_monitoring_command_outbox(next_attempt_at, id)
    WHERE state IN ('pending','publishing');

CREATE INDEX node_monitoring_command_outbox_claim_idx
    ON node_monitoring_command_outbox(claimed_until, id)
    WHERE state = 'publishing';

CREATE FUNCTION protect_node_monitoring_command_outbox()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node monitoring command outbox facts are append-only';
    END IF;
    IF ROW(NEW.id,NEW.event_id,NEW.node_id,NEW.config_revision,NEW.subject,NEW.message_id,
           NEW.payload,NEW.payload_sha256,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.event_id,OLD.node_id,OLD.config_revision,OLD.subject,OLD.message_id,
           OLD.payload,OLD.payload_sha256,OLD.created_at) THEN
        RAISE EXCEPTION 'node monitoring command outbox identity is immutable';
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

CREATE TRIGGER node_monitoring_command_outbox_append_only
BEFORE INSERT OR UPDATE OR DELETE ON node_monitoring_command_outbox
FOR EACH ROW EXECUTE FUNCTION protect_node_monitoring_command_outbox();

REVOKE ALL ON FUNCTION protect_node_monitoring_command_outbox() FROM PUBLIC;
