LOCK TABLE schema_migrations, audit_events, platform_system_cleanup_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_331_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 330 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 330 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=330 AND
        migration_id='330_traffic_package_cycle_deductions' AND
        checksum_sha256='86501d58b9f46cc864e4a515ace7018be8cb818259d2115a1fb08b12ea12b5d9' AND
        down_checksum_sha256='b57a58a9da12689fac74933a55e33da098701148928705807a1790da957a15ee' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.audit_event_archive') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 331 requires the exact verified 330 release head' USING ERRCODE='P3310';
    END IF;
END;
$migration_331_up$;

-- FX01: audit_events is a per-scope hash chain, so expired rows are never
-- simply deleted. The cleanup role (cdnca_retention_cleanup, see 320) copies
-- the oldest expired, chain-verified prefix of a scope into audit_event_archive
-- and advances that scope's checkpoint (position + hash of the last archived
-- row) in the same transaction. Rows at or below the checkpoint are then
-- deleted from audit_events unless they are still pinned:
--   * referenced by a foreign key (audit_event_pinned_331 reads pg_constraint,
--     so later foreign keys are covered too),
--   * the scope's chain head (Append continues from it),
--   * the newest row of its (scope, action, resource_type, resource_id) group
--     (business code reads the latest credential issuance, scan token, ...),
--   * a cache.* row (cache read paths count them for integrity).
-- Chain verification starts from the checkpoint.

-- Referencing columns without an index make every RESTRICT check a scan.
CREATE INDEX cache_operation_target_results_audit_event_331_idx ON cache_operation_target_results(audit_event_id);
CREATE INDEX cname_allocation_requests_audit_event_331_idx ON cname_allocation_requests(audit_event_id);
CREATE INDEX notification_delivery_command_receipts_108_audit_event_331_idx ON notification_delivery_command_receipts_108(audit_event_id);
CREATE INDEX notification_delivery_facts_108_audit_event_331_idx ON notification_delivery_facts_108(audit_event_id);

CREATE TABLE audit_event_archive (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    stream_position bigint NOT NULL CHECK (stream_position > 0),
    actor_user_id uuid,
    action text NOT NULL CHECK (action <> ''),
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_id text NOT NULL CHECK (resource_id <> ''),
    request_id text NOT NULL CHECK (request_id <> ''),
    result text NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    previous_hash bytea,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL,
    archived_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (scope_id, stream_position)
);

CREATE TABLE audit_chain_checkpoints (
    scope_id uuid PRIMARY KEY,
    through_position bigint NOT NULL CHECK (through_position > 0),
    through_hash bytea NOT NULL CHECK (octet_length(through_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (scope_id, through_position) REFERENCES audit_event_archive(scope_id, stream_position)
);

-- Oldest instant an audit row of the given kind may keep (login = auth.login,
-- operation = everything else); NULL when the setting is 0 (keep forever).
DO $migration_331_cutoff$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.retention_cleanup_cutoff_331(setting text) RETURNS timestamptz
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        DECLARE
            days integer;
        BEGIN
            IF setting NOT IN ('login_records_days', 'operation_records_days', 'node_traffic_history_days') THEN
                RAISE EXCEPTION 'unknown retention setting %%', setting USING ERRCODE='P3311';
            END IF;
            SELECT max((settings->>setting)::integer) INTO days FROM %I.platform_system_cleanup_settings
                WHERE settings ? setting;
            days := COALESCE(days, CASE setting WHEN 'login_records_days' THEN 30
                WHEN 'operation_records_days' THEN 365 ELSE 45 END);
            IF days < 0 OR days > 3650 THEN
                RAISE EXCEPTION 'retention setting %% is out of range', setting USING ERRCODE='P3311';
            END IF;
            IF days = 0 THEN
                RETURN NULL;
            END IF;
            RETURN transaction_timestamp() - make_interval(days => days);
        END;
        $body$;
    $ddl$, current_schema(), current_schema());
END;
$migration_331_cutoff$;

-- True while the row must stay in audit_events (see the rules above).
DO $migration_331_pinned$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.audit_event_pinned_331(event_id uuid) RETURNS boolean
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        DECLARE
            event %I.audit_events%%ROWTYPE;
            reference record;
            referenced boolean;
        BEGIN
            SELECT * INTO event FROM %I.audit_events WHERE id = event_id;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
            IF event.action LIKE 'cache.%%' OR NOT EXISTS (
                SELECT 1 FROM %I.audit_events newer WHERE newer.scope_id = event.scope_id
                  AND newer.stream_position > event.stream_position) OR NOT EXISTS (
                SELECT 1 FROM %I.audit_events newer WHERE newer.scope_id = event.scope_id
                  AND newer.action = event.action AND newer.resource_type = event.resource_type
                  AND newer.resource_id = event.resource_id AND newer.stream_position > event.stream_position) THEN
                RETURN true;
            END IF;
            FOR reference IN
                SELECT constraint_row.conrelid::regclass AS relation, attribute.attname AS column_name
                FROM pg_constraint constraint_row
                JOIN pg_attribute attribute ON attribute.attrelid = constraint_row.conrelid
                    AND attribute.attnum = constraint_row.conkey[1]
                WHERE constraint_row.contype = 'f' AND constraint_row.confrelid = %L::regclass
            LOOP
                EXECUTE format('SELECT EXISTS (SELECT 1 FROM %%s WHERE %%I = $1)', reference.relation, reference.column_name)
                    INTO referenced USING event_id;
                IF referenced THEN
                    RETURN true;
                END IF;
            END LOOP;
            RETURN false;
        END;
        $body$;
    $ddl$, current_schema(), current_schema(), current_schema(), current_schema(), current_schema(),
        current_schema() || '.audit_events');
END;
$migration_331_pinned$;

-- Archive rows are exact copies of audit_events rows, written only by the
-- cleanup role; afterwards they are immutable.
CREATE FUNCTION guard_audit_event_archive_insert_331()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF current_user <> 'cdnca_retention_cleanup' OR NOT EXISTS (
        SELECT 1 FROM audit_events source WHERE source.id = NEW.id AND source.scope_id = NEW.scope_id
          AND source.stream_position = NEW.stream_position
          AND source.actor_user_id IS NOT DISTINCT FROM NEW.actor_user_id
          AND source.action = NEW.action AND source.resource_type = NEW.resource_type
          AND source.resource_id = NEW.resource_id AND source.request_id = NEW.request_id
          AND source.result = NEW.result AND source.payload = NEW.payload
          AND source.previous_hash IS NOT DISTINCT FROM NEW.previous_hash
          AND source.event_hash = NEW.event_hash AND source.occurred_at = NEW.occurred_at
    ) THEN
        RAISE EXCEPTION 'audit archive accepts only exact copies from the cleanup role' USING ERRCODE='P3312';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION reject_audit_archive_mutation_331()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE='P3312';
END;
$function$;

CREATE TRIGGER audit_event_archive_insert_331 BEFORE INSERT ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION guard_audit_event_archive_insert_331();
CREATE TRIGGER audit_event_archive_immutable_331 BEFORE UPDATE OR DELETE ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION reject_audit_archive_mutation_331();
CREATE TRIGGER audit_event_archive_no_truncate_331 BEFORE TRUNCATE ON audit_event_archive
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_archive_mutation_331();

-- A checkpoint only moves forward, only by the cleanup role, and always to an
-- archived row (the foreign key) whose hash it records.
CREATE FUNCTION guard_audit_chain_checkpoint_331()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF current_user <> 'cdnca_retention_cleanup' OR
       TG_OP = 'UPDATE' AND (NEW.scope_id <> OLD.scope_id OR NEW.through_position <= OLD.through_position) OR
       NOT EXISTS (SELECT 1 FROM audit_event_archive archived WHERE archived.scope_id = NEW.scope_id
           AND archived.stream_position = NEW.through_position AND archived.event_hash = NEW.through_hash) OR
       EXISTS (SELECT 1 FROM generate_series(COALESCE(CASE WHEN TG_OP = 'UPDATE' THEN OLD.through_position END, 0) + 1,
           NEW.through_position) position WHERE NOT EXISTS (SELECT 1 FROM audit_event_archive archived
           WHERE archived.scope_id = NEW.scope_id AND archived.stream_position = position)) THEN
        RAISE EXCEPTION 'audit chain checkpoint must advance over archived rows' USING ERRCODE='P3313';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER audit_chain_checkpoints_guard_331 BEFORE INSERT OR UPDATE ON audit_chain_checkpoints
    FOR EACH ROW EXECUTE FUNCTION guard_audit_chain_checkpoint_331();
CREATE TRIGGER audit_chain_checkpoints_immutable_331 BEFORE DELETE ON audit_chain_checkpoints
    FOR EACH ROW EXECUTE FUNCTION reject_audit_archive_mutation_331();
CREATE TRIGGER audit_chain_checkpoints_no_truncate_331 BEFORE TRUNCATE ON audit_chain_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_archive_mutation_331();

-- audit_events stays append-only for everyone else. The cleanup role may only
-- delete an unpinned row that is archived unchanged and below the checkpoint.
CREATE FUNCTION guard_audit_event_retention_delete_331()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM audit_chain_checkpoints checkpoint WHERE checkpoint.scope_id = OLD.scope_id
           AND checkpoint.through_position >= OLD.stream_position) OR
       NOT EXISTS (SELECT 1 FROM audit_event_archive archived WHERE archived.id = OLD.id
           AND archived.scope_id = OLD.scope_id AND archived.stream_position = OLD.stream_position
           AND archived.event_hash = OLD.event_hash) OR
       audit_event_pinned_331(OLD.id) THEN
        RAISE EXCEPTION 'audit event is not archived or still pinned' USING ERRCODE='P3314';
    END IF;
    RETURN OLD;
END;
$function$;

DROP TRIGGER audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
CREATE TRIGGER audit_events_append_only_del BEFORE DELETE ON audit_events
    FOR EACH ROW WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION prevent_audit_event_mutation();
CREATE TRIGGER audit_events_retention_331 BEFORE DELETE ON audit_events
    FOR EACH ROW WHEN (current_user = 'cdnca_retention_cleanup') EXECUTE FUNCTION guard_audit_event_retention_delete_331();

DO $migration_331_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
        GRANT SELECT, DELETE ON audit_events TO cdnca_retention_cleanup;
        GRANT SELECT, INSERT ON audit_event_archive TO cdnca_retention_cleanup;
        GRANT SELECT, INSERT, UPDATE ON audit_chain_checkpoints TO cdnca_retention_cleanup;
        GRANT EXECUTE ON FUNCTION retention_cleanup_cutoff_331(text) TO cdnca_retention_cleanup;
        GRANT EXECUTE ON FUNCTION audit_event_pinned_331(uuid) TO cdnca_retention_cleanup;
    END IF;
END;
$migration_331_grants$;
