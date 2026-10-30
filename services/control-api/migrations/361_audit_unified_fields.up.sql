LOCK TABLE schema_migrations, audit_events, audit_event_archive IN ACCESS EXCLUSIVE MODE;

DO $migration_361_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 360 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 360 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=360 AND
        migration_id='360_theme_packages' AND
        checksum_sha256='7f508678b3f75627c6f0c7e7e9237bfc8e6d610cd70e3c834a7d1f7b649f4a3d' AND
        down_checksum_sha256='601053b7cf96761a25422bb1d6a8813833c0d24c6cd3eb4cc29e958964d82289' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.guard_audit_event_archive_insert_331()') IS NULL OR
       to_regprocedure(current_schema() || '.guard_audit_event_archive_insert_361()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 361 requires the exact verified 360 release head' USING ERRCODE='P3610';
    END IF;
END;
$migration_361_up$;

-- unified-log: formal columns for what every log line shows. category is the
-- event catalog category of the action (internal/audit/catalog.go), written
-- by audit.Append; actor_kind says who acted (a user, the system, a plugin or
-- a node) and actor_ref identifies a non-user actor or the credential a user
-- used; source_ip is the client address; reason_code explains denied/failure
-- rows; changes is the before -> after summary (secrets redacted). All of
-- them are part of the version-2 event hash.
ALTER TABLE audit_events
    ADD COLUMN category text NOT NULL DEFAULT 'other',
    ADD COLUMN actor_kind text NOT NULL DEFAULT 'system',
    ADD COLUMN actor_ref text NOT NULL DEFAULT '',
    ADD COLUMN source_ip text NOT NULL DEFAULT '',
    ADD COLUMN reason_code text NOT NULL DEFAULT '',
    ADD COLUMN changes jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT audit_events_category_361 CHECK (category IN ('admin', 'user', 'auth', 'site', 'security',
        'rule', 'finance', 'package', 'plugin', 'node', 'dns', 'cert', 'system', 'other')),
    ADD CONSTRAINT audit_events_actor_kind_361 CHECK (actor_kind IN ('user', 'system', 'plugin', 'node')),
    ADD CONSTRAINT audit_events_actor_user_361 CHECK (actor_kind <> 'user' OR actor_user_id IS NOT NULL),
    ADD CONSTRAINT audit_events_actor_ref_361 CHECK (length(actor_ref) <= 200),
    ADD CONSTRAINT audit_events_source_ip_361 CHECK (source_ip = '' OR (source_ip !~ '/' AND
        masklen(source_ip::inet) = CASE family(source_ip::inet) WHEN 4 THEN 32 ELSE 128 END)),
    ADD CONSTRAINT audit_events_reason_code_361 CHECK (length(reason_code) <= 200),
    ADD CONSTRAINT audit_events_changes_361 CHECK (jsonb_typeof(changes) = 'array');

-- Log center reads: one category across scopes (platform), one scope's
-- category, an actor's history, an address's history.
CREATE INDEX audit_events_category_time_361 ON audit_events (category, occurred_at DESC);
CREATE INDEX audit_events_scope_category_time_361 ON audit_events (scope_id, category, occurred_at DESC);
CREATE INDEX audit_events_actor_time_361 ON audit_events (actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX audit_events_source_ip_time_361 ON audit_events (source_ip, occurred_at DESC)
    WHERE source_ip <> '';

ALTER TABLE audit_event_archive
    ADD COLUMN category text NOT NULL DEFAULT 'other',
    ADD COLUMN actor_kind text NOT NULL DEFAULT 'system',
    ADD COLUMN actor_ref text NOT NULL DEFAULT '',
    ADD COLUMN source_ip text NOT NULL DEFAULT '',
    ADD COLUMN reason_code text NOT NULL DEFAULT '',
    ADD COLUMN changes jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX audit_event_archive_category_time_361 ON audit_event_archive (category, occurred_at DESC);

-- Archive rows stay exact copies, now including the new columns.
CREATE FUNCTION guard_audit_event_archive_insert_361()
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
          AND source.category = NEW.category AND source.actor_kind = NEW.actor_kind
          AND source.actor_ref = NEW.actor_ref AND source.source_ip = NEW.source_ip
          AND source.reason_code = NEW.reason_code AND source.changes = NEW.changes
    ) THEN
        RAISE EXCEPTION 'audit archive accepts only exact copies from the cleanup role' USING ERRCODE='P3612';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION guard_audit_event_archive_insert_361() FROM PUBLIC;

DROP TRIGGER audit_event_archive_insert_331 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_insert_361 BEFORE INSERT ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION guard_audit_event_archive_insert_361();

-- Per-category retention (unified-log): the cleanup worker advances the
-- checkpoint over rows older than the shortest retention, deletes each row
-- once its own category expires, then purges archive copies of rows that left
-- audit_events, so the archive does not grow without bound. Only the cleanup
-- role may purge, only rows already gone from audit_events and below the
-- checkpoint (the checkpoint row anchors the chain and stays).
CREATE FUNCTION guard_audit_event_archive_purge_361()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_events event WHERE event.id = OLD.id) OR NOT EXISTS (
        SELECT 1 FROM audit_chain_checkpoints checkpoint WHERE checkpoint.scope_id = OLD.scope_id
          AND checkpoint.through_position > OLD.stream_position) THEN
        RAISE EXCEPTION 'audit archive row is still in audit_events or anchors the checkpoint' USING ERRCODE='P3614';
    END IF;
    RETURN OLD;
END;
$function$;
REVOKE ALL ON FUNCTION guard_audit_event_archive_purge_361() FROM PUBLIC;

DROP TRIGGER audit_event_archive_immutable_331 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_immutable_361 BEFORE UPDATE ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION reject_audit_archive_mutation_331();
CREATE TRIGGER audit_event_archive_no_delete_361 BEFORE DELETE ON audit_event_archive
    FOR EACH ROW WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION reject_audit_archive_mutation_331();
CREATE TRIGGER audit_event_archive_purge_361 BEFORE DELETE ON audit_event_archive
    FOR EACH ROW WHEN (current_user = 'cdnca_retention_cleanup') EXECUTE FUNCTION guard_audit_event_archive_purge_361();

DO $migration_361_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        GRANT DELETE ON audit_event_archive TO cdnca_retention_cleanup;
    END IF;
END;
$migration_361_grants$;
