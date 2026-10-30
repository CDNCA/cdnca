DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 82 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 82 THEN
        RAISE EXCEPTION 'analytics observability state requires frozen migration head 082'
            USING ERRCODE = 'P8300';
    END IF;
END;
$$;

CREATE TABLE analytics_history_streams (
    installation_id text NOT NULL
        REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    nats_domain text NOT NULL DEFAULT '' CHECK (
        nats_domain = '' OR nats_domain ~ '^[A-Za-z0-9_-]{1,128}$'
    ),
    stream_name text NOT NULL CHECK (
        stream_name ~ '^[A-Za-z0-9_-]{1,128}$'
    ),
    durable_name text NOT NULL CHECK (
        durable_name ~ '^[A-Za-z0-9_-]{1,128}$'
    ),
    stream_created_unix_nano numeric(20,0) NOT NULL CHECK (
        stream_created_unix_nano BETWEEN 1 AND 18446744073709551615
    ),
    consumer_created_unix_nano numeric(20,0) NOT NULL CHECK (
        consumer_created_unix_nano BETWEEN 1 AND 18446744073709551615 AND
        consumer_created_unix_nano >= stream_created_unix_nano
    ),
    history_epoch uuid PRIMARY KEY CHECK (
        history_epoch <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    history_start_sequence numeric(20,0) NOT NULL CHECK (
        history_start_sequence BETWEEN 1 AND 18446744073709551615
    ),
    history_start_at timestamptz NOT NULL CHECK (isfinite(history_start_at)),
    legacy_baseline_kind text NOT NULL CHECK (
        legacy_baseline_kind IN ('none', 'current_visible_state')
    ),
    legacy_baseline_at timestamptz,
    legacy_baseline_sha256 bytea,
    broker_consumer_ack_floor numeric(20,0) NOT NULL CHECK (
        broker_consumer_ack_floor BETWEEN 0 AND 18446744073709551615
    ),
    broker_stream_ack_floor numeric(20,0) NOT NULL CHECK (
        broker_stream_ack_floor BETWEEN history_start_sequence - 1 AND 18446744073709551615
    ),
    prepared_stream_floor numeric(20,0) NOT NULL CHECK (
        prepared_stream_floor BETWEEN history_start_sequence - 1 AND 18446744073709551615
    ),
    committed_stream_ack_floor numeric(20,0) GENERATED ALWAYS AS (
        LEAST(broker_stream_ack_floor, prepared_stream_floor)
    ) STORED,
    revision numeric(20,0) NOT NULL CHECK (
        revision BETWEEN 1 AND 18446744073709551615
    ),
    last_reconciled_at timestamptz NOT NULL CHECK (isfinite(last_reconciled_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    retired_at timestamptz CHECK (retired_at IS NULL OR isfinite(retired_at)),
    UNIQUE (
        installation_id, nats_domain, stream_name, durable_name,
        stream_created_unix_nano, consumer_created_unix_nano
    ),
    CHECK (
        (legacy_baseline_kind = 'none' AND legacy_baseline_at IS NULL AND
         legacy_baseline_sha256 IS NULL AND history_start_sequence = 1) OR
        (legacy_baseline_kind = 'current_visible_state' AND legacy_baseline_at IS NOT NULL AND
         isfinite(legacy_baseline_at) AND legacy_baseline_at <= history_start_at AND
         legacy_baseline_sha256 IS NOT NULL AND octet_length(legacy_baseline_sha256) = 32)
    ),
    CHECK (updated_at >= created_at),
    CHECK (history_start_at <= created_at),
    CHECK (last_reconciled_at BETWEEN created_at AND updated_at),
    CHECK (retired_at IS NULL OR retired_at = updated_at)
);

COMMENT ON COLUMN analytics_history_streams.legacy_baseline_kind IS
    'current_visible_state declares only the cutover-visible legacy state; it never represents reconstructed history';

CREATE UNIQUE INDEX analytics_history_streams_one_active_identity_idx
    ON analytics_history_streams(installation_id, nats_domain, stream_name, durable_name)
    WHERE retired_at IS NULL;

CREATE FUNCTION guard_analytics_history_stream_083()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous_stream_created numeric(20,0);
    previous_consumer_created numeric(20,0);
    previous_retired_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(
            NEW.installation_id || chr(31) || NEW.nats_domain || chr(31) ||
            NEW.stream_name || chr(31) || NEW.durable_name, 83
        ));
        SELECT stream_created_unix_nano, consumer_created_unix_nano, retired_at
        INTO previous_stream_created, previous_consumer_created, previous_retired_at
        FROM analytics_history_streams
        WHERE installation_id = NEW.installation_id
          AND nats_domain = NEW.nats_domain
          AND stream_name = NEW.stream_name
          AND durable_name = NEW.durable_name
        ORDER BY consumer_created_unix_nano DESC, stream_created_unix_nano DESC
        LIMIT 1;
        IF NEW.revision <> 1 OR
           NEW.updated_at <> NEW.created_at OR
           NEW.last_reconciled_at <> NEW.created_at OR
           NEW.retired_at IS NOT NULL OR
           NEW.broker_stream_ack_floor <> NEW.history_start_sequence - 1 OR
           NEW.prepared_stream_floor <> NEW.history_start_sequence - 1 OR
           (previous_consumer_created IS NOT NULL AND (
               previous_retired_at IS NULL OR
               NEW.stream_created_unix_nano < previous_stream_created OR
               NEW.consumer_created_unix_nano <= previous_consumer_created OR
               NEW.created_at < previous_retired_at
           )) THEN
            RAISE EXCEPTION 'analytics history generations require an immutable non-overlapping broker identity'
                USING ERRCODE = 'P8301';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'analytics history streams cannot be deleted'
            USING ERRCODE = 'P8302';
    END IF;
    IF OLD.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'retired analytics history streams are immutable'
            USING ERRCODE = 'P8301';
    END IF;
    IF NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
       NEW.nats_domain IS DISTINCT FROM OLD.nats_domain OR
       NEW.stream_name IS DISTINCT FROM OLD.stream_name OR
       NEW.durable_name IS DISTINCT FROM OLD.durable_name OR
       NEW.stream_created_unix_nano IS DISTINCT FROM OLD.stream_created_unix_nano OR
       NEW.consumer_created_unix_nano IS DISTINCT FROM OLD.consumer_created_unix_nano OR
       NEW.history_epoch IS DISTINCT FROM OLD.history_epoch OR
       NEW.history_start_sequence IS DISTINCT FROM OLD.history_start_sequence OR
       NEW.history_start_at IS DISTINCT FROM OLD.history_start_at OR
       NEW.legacy_baseline_kind IS DISTINCT FROM OLD.legacy_baseline_kind OR
       NEW.legacy_baseline_at IS DISTINCT FROM OLD.legacy_baseline_at OR
       NEW.legacy_baseline_sha256 IS DISTINCT FROM OLD.legacy_baseline_sha256 OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'analytics history identity creation boundary and baseline are immutable'
            USING ERRCODE = 'P8301';
    END IF;
    IF NEW.broker_consumer_ack_floor < OLD.broker_consumer_ack_floor OR
       NEW.broker_stream_ack_floor < OLD.broker_stream_ack_floor OR
       NEW.prepared_stream_floor < OLD.prepared_stream_floor OR
       NEW.revision <> OLD.revision + 1 OR
       NEW.last_reconciled_at < OLD.last_reconciled_at OR
       NEW.updated_at <= OLD.updated_at THEN
        RAISE EXCEPTION 'analytics history floors revision and reconciliation time must advance monotonically'
            USING ERRCODE = 'P8301';
    END IF;
    IF NEW.broker_consumer_ack_floor = OLD.broker_consumer_ack_floor AND
       NEW.broker_stream_ack_floor = OLD.broker_stream_ack_floor AND
       NEW.prepared_stream_floor = OLD.prepared_stream_floor AND
       NEW.retired_at IS NOT DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'analytics history revisions require broker progress preparation progress or retirement'
            USING ERRCODE = 'P8301';
    END IF;
    IF NEW.retired_at IS NOT NULL AND NEW.retired_at <> NEW.updated_at THEN
        RAISE EXCEPTION 'analytics history retirement must use the revision time'
            USING ERRCODE = 'P8301';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER analytics_history_streams_guard_083
BEFORE INSERT OR UPDATE OR DELETE ON analytics_history_streams
FOR EACH ROW EXECUTE FUNCTION guard_analytics_history_stream_083();

CREATE FUNCTION prevent_analytics_history_stream_truncate_083()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics history streams cannot be truncated'
        USING ERRCODE = 'P8302';
END;
$$;

CREATE TRIGGER analytics_history_streams_truncate_guard_083
BEFORE TRUNCATE ON analytics_history_streams
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_history_stream_truncate_083();

REVOKE ALL ON analytics_history_streams FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_history_stream_083() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_history_stream_truncate_083() FROM PUBLIC;
