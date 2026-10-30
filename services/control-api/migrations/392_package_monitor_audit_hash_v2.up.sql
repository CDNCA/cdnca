LOCK TABLE schema_migrations, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_392_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 391 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 391 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=391 AND
        migration_id='391_http_policy_regex_rules' AND
        checksum_sha256='3394a5f15823e3f7fc28fd65d176a4afd2e4f0bd586232dfc94a572b6d1bbc66' AND
        down_checksum_sha256='ff8424ee96e74fc490a9c0222728fdbba4ce679d4d7c26499da132bfb8442dd0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.bind_package_monitor_audit_clock_078()') IS NULL
       OR to_regprocedure(current_schema() || '.package_monitor_audit_hash_392(uuid,uuid,bigint,uuid,text,text,text,text,text,jsonb,bytea,timestamptz,text,text,text,text,text,jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 392 requires the exact verified 391 release head' USING ERRCODE='P3920';
    END IF;
END;
$migration_392_up$;

-- 392（r136 testdebt4 占位：接在 391 之后；合入时主会话改号）。
-- 361 made the audit event hash version 2 (internal/audit/log.go
-- canonicalVersion): it also covers category, actor_kind, actor_ref,
-- source_ip, reason_code and changes. Package monitor audit rows get their
-- occurred_at from the database evaluation clock, so 078's insert trigger
-- recomputes event_hash; it still produced the version-1 hash, and every such
-- row failed audit.VerifyScope ("hash mismatch"). The trigger now produces the
-- version-2 canonical bytes, field for field the same as audit.computeHash.
CREATE FUNCTION package_monitor_audit_hash_392(
    event_id uuid,
    event_scope_id uuid,
    event_stream_position bigint,
    event_actor_user_id uuid,
    event_action text,
    event_resource_type text,
    event_resource_id text,
    event_request_id text,
    event_result text,
    event_payload jsonb,
    event_previous_hash bytea,
    event_occurred_at timestamptz,
    event_category text,
    event_actor_kind text,
    event_actor_ref text,
    event_source_ip text,
    event_reason_code text,
    event_changes jsonb
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT sha256(convert_to(
        '{"version":2,"id":' || package_monitor_go_json_string_078(event_id::text) ||
        ',"scope_id":' || package_monitor_go_json_string_078(event_scope_id::text) ||
        ',"stream_position":' || event_stream_position::text ||
        ',"actor_user_id":' || COALESCE(package_monitor_go_json_string_078(event_actor_user_id::text), 'null') ||
        ',"action":' || package_monitor_go_json_string_078(event_action) ||
        ',"resource_type":' || package_monitor_go_json_string_078(event_resource_type) ||
        ',"resource_id":' || package_monitor_go_json_string_078(event_resource_id) ||
        ',"request_id":' || package_monitor_go_json_string_078(event_request_id) ||
        ',"result":' || package_monitor_go_json_string_078(event_result) ||
        ',"payload":' || package_monitor_json_canonical_078(event_payload) ||
        ',"previous_hash":' || package_monitor_go_json_string_078(COALESCE(encode(event_previous_hash, 'hex'), '')) ||
        ',"occurred_at":' || package_monitor_go_json_string_078(package_monitor_rfc3339nano_078(event_occurred_at)) ||
        ',"category":' || package_monitor_go_json_string_078(event_category) ||
        ',"actor_kind":' || package_monitor_go_json_string_078(event_actor_kind) ||
        ',"actor_ref":' || package_monitor_go_json_string_078(event_actor_ref) ||
        ',"source_ip":' || package_monitor_go_json_string_078(event_source_ip) ||
        ',"reason_code":' || package_monitor_go_json_string_078(event_reason_code) ||
        ',"changes":' || package_monitor_json_canonical_078(event_changes) ||
        '}',
        'UTF8'
    ));
$$;
REVOKE ALL ON FUNCTION package_monitor_audit_hash_392(
    uuid, uuid, bigint, uuid, text, text, text, text, text, jsonb, bytea, timestamptz,
    text, text, text, text, text, jsonb
) FROM PUBLIC;

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
    NEW.event_hash := package_monitor_audit_hash_392(
        NEW.id, NEW.scope_id, NEW.stream_position, NEW.actor_user_id,
        NEW.action, NEW.resource_type, NEW.resource_id, NEW.request_id,
        NEW.result, NEW.payload, NEW.previous_hash, NEW.occurred_at,
        NEW.category, NEW.actor_kind, NEW.actor_ref, NEW.source_ip,
        NEW.reason_code, NEW.changes
    );
    RETURN NEW;
END;
$$;
