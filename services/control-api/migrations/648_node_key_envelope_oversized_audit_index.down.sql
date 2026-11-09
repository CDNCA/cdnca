LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_648_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 648 OR
       (SELECT max(version) FROM schema_migrations) <> 648 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=648 AND
        migration_id='648_node_key_envelope_oversized_audit_index' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 648 down requires the exact verified migration head' USING ERRCODE='P6481';
    END IF;
END;
$migration_648_down$;

-- The index only speeds up a read; the audit events stay.
DROP INDEX audit_events_node_key_envelope_oversized_648_idx;
