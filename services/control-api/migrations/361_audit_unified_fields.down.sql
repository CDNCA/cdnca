LOCK TABLE schema_migrations, audit_events, audit_event_archive IN ACCESS EXCLUSIVE MODE;

DO $migration_361_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 361 OR
       (SELECT max(version) FROM schema_migrations) <> 361 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=361 AND
        migration_id='361_audit_unified_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 361 down requires the exact verified migration head' USING ERRCODE='P3611';
    END IF;
    -- Version-2 hashes cover the new columns: dropping them would make every
    -- such row fail chain verification.
    IF EXISTS (SELECT 1 FROM audit_events) OR EXISTS (SELECT 1 FROM audit_event_archive) THEN
        RAISE EXCEPTION 'migration 361 down refuses to drop hashed audit columns while audit rows exist'
            USING ERRCODE='P3613';
    END IF;
END;
$migration_361_down$;

DO $migration_361_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE DELETE ON audit_event_archive FROM cdnca_retention_cleanup;
    END IF;
END;
$migration_361_revoke$;
DROP TRIGGER audit_event_archive_purge_361 ON audit_event_archive;
DROP TRIGGER audit_event_archive_no_delete_361 ON audit_event_archive;
DROP TRIGGER audit_event_archive_immutable_361 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_immutable_331 BEFORE UPDATE OR DELETE ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION reject_audit_archive_mutation_331();
DROP FUNCTION guard_audit_event_archive_purge_361();

DROP TRIGGER audit_event_archive_insert_361 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_insert_331 BEFORE INSERT ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION guard_audit_event_archive_insert_331();
DROP FUNCTION guard_audit_event_archive_insert_361();

DROP INDEX audit_event_archive_category_time_361;
ALTER TABLE audit_event_archive
    DROP COLUMN changes, DROP COLUMN reason_code, DROP COLUMN source_ip,
    DROP COLUMN actor_ref, DROP COLUMN actor_kind, DROP COLUMN category;

DROP INDEX audit_events_source_ip_time_361;
DROP INDEX audit_events_actor_time_361;
DROP INDEX audit_events_scope_category_time_361;
DROP INDEX audit_events_category_time_361;
ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_changes_361, DROP CONSTRAINT audit_events_reason_code_361,
    DROP CONSTRAINT audit_events_source_ip_361, DROP CONSTRAINT audit_events_actor_ref_361,
    DROP CONSTRAINT audit_events_actor_user_361, DROP CONSTRAINT audit_events_actor_kind_361,
    DROP CONSTRAINT audit_events_category_361,
    DROP COLUMN changes, DROP COLUMN reason_code, DROP COLUMN source_ip,
    DROP COLUMN actor_ref, DROP COLUMN actor_kind, DROP COLUMN category;
