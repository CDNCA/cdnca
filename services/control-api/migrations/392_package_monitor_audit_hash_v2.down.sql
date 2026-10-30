LOCK TABLE schema_migrations, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_392_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 392 OR
       (SELECT max(version) FROM schema_migrations) <> 392 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=392 AND
        migration_id='392_package_monitor_audit_hash_v2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 392 down requires the exact verified migration head' USING ERRCODE='P3921';
    END IF;
END;
$migration_392_down$;

-- Rows written under 392 keep their version-2 hashes; only the trigger goes
-- back to the 078 definition.
CREATE OR REPLACE FUNCTION bind_package_monitor_audit_clock_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    payload_clock_id uuid;
    payload_evaluated_at_text text;
    payload_evaluated_at timestamptz;
    database_evaluated_at timestamptz;
BEGIN
    IF jsonb_typeof(NEW.payload -> 'evaluation_clock_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.payload -> 'evaluated_at') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END IF;
    payload_evaluated_at_text := NEW.payload ->> 'evaluated_at';
    BEGIN
        payload_clock_id := (NEW.payload ->> 'evaluation_clock_id')::uuid;
        payload_evaluated_at := payload_evaluated_at_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END;
    SELECT clock.evaluated_at
    INTO database_evaluated_at
    FROM package_monitor_evaluation_clocks AS clock
    WHERE clock.evaluation_clock_id = payload_clock_id
      AND clock.transaction_id = pg_current_xact_id()::text;
    IF NOT FOUND OR NOT isfinite(payload_evaluated_at)
       OR payload_evaluated_at IS DISTINCT FROM database_evaluated_at
       OR payload_evaluated_at_text IS DISTINCT FROM
           package_monitor_rfc3339nano_078(database_evaluated_at) THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END IF;
    NEW.occurred_at := database_evaluated_at;
    NEW.event_hash := package_monitor_audit_hash_078(
        NEW.id, NEW.scope_id, NEW.stream_position, NEW.actor_user_id,
        NEW.action, NEW.resource_type, NEW.resource_id, NEW.request_id,
        NEW.result, NEW.payload, NEW.previous_hash, NEW.occurred_at
    );
    RETURN NEW;
END;
$$;

DROP FUNCTION package_monitor_audit_hash_392(
    uuid, uuid, bigint, uuid, text, text, text, text, text, jsonb, bytea, timestamptz,
    text, text, text, text, text, jsonb
);
