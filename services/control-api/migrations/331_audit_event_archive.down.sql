LOCK TABLE schema_migrations, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_331_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 331 OR
       (SELECT max(version) FROM schema_migrations) <> 331 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=331 AND
        migration_id='331_audit_event_archive' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 331 down requires the exact verified migration head' USING ERRCODE='P3315';
    END IF;
    -- Once rows left audit_events the full chain only exists with the archive.
    IF EXISTS (SELECT 1 FROM audit_chain_checkpoints) THEN
        RAISE EXCEPTION 'migration 331 down refuses to drop archived audit history' USING ERRCODE='P3315';
    END IF;
END;
$migration_331_down$;

DO $migration_331_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE SELECT, DELETE ON audit_events FROM cdnca_retention_cleanup;
    END IF;
END;
$migration_331_revoke$;

-- Restores the 001 guard: audit_events rejects every update and delete.
DROP TRIGGER audit_events_retention_331 ON audit_events;
DROP TRIGGER audit_events_append_only_del ON audit_events;
DROP TRIGGER audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
DROP FUNCTION guard_audit_event_retention_delete_331();
DROP TABLE audit_chain_checkpoints;
DROP TABLE audit_event_archive;
DROP FUNCTION guard_audit_chain_checkpoint_331();
DROP FUNCTION guard_audit_event_archive_insert_331();
DROP FUNCTION reject_audit_archive_mutation_331();
DROP FUNCTION audit_event_pinned_331(uuid);
DROP FUNCTION retention_cleanup_cutoff_331(text);
DROP INDEX notification_delivery_facts_108_audit_event_331_idx;
DROP INDEX notification_delivery_command_receipts_108_audit_event_331_idx;
DROP INDEX cname_allocation_requests_audit_event_331_idx;
DROP INDEX cache_operation_target_results_audit_event_331_idx;
