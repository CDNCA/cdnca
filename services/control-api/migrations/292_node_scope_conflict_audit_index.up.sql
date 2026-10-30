LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_292_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 291 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 291 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=291 AND
        migration_id='291_multi_tenant_node_gate' AND
        checksum_sha256='c843962a9696c76cd1038ad51bbc23d13069dcfb231584098827e307142dd559' AND
        down_checksum_sha256='58a6a8dd74b355db9b043b48d62f536704904c96c74db0cb3017e61df038e488' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.audit_events_node_scope_conflict_292_idx') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 292 requires the exact verified 291 release head' USING ERRCODE='P2920';
    END IF;
END;
$migration_292_up$;

-- The node detail page lists publications refused on a node for conflicting
-- with another tenant there (edge_publication.node_scope_conflict, resource
-- = the node). Only those events are indexed.
CREATE INDEX audit_events_node_scope_conflict_292_idx ON audit_events (resource_id, occurred_at DESC)
    WHERE action = 'edge_publication.node_scope_conflict' AND resource_type = 'node';
