LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_292_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 292 OR
       (SELECT max(version) FROM schema_migrations) <> 292 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=292 AND
        migration_id='292_node_scope_conflict_audit_index' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 292 down requires the exact verified migration head' USING ERRCODE='P2921';
    END IF;
END;
$migration_292_down$;

-- The index only speeds up a read; the audit events stay.
DROP INDEX audit_events_node_scope_conflict_292_idx;
