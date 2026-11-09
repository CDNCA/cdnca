-- 648（节点「旧配置仍生效」查询的审计部分索引；前驱 647_node_packaging_toolset）：只加索引，不改数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_648_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 647 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 647 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=647 AND
        migration_id='647_node_packaging_toolset' AND
        checksum_sha256='fe7366236a4001b54baefe6e05c8dff654d95eff886833370bde924073f176dd' AND
        down_checksum_sha256='24a2c45a73ef46e6c4edddae5a8cf09cf28d55c63b47e352d58aacf1e88bec5d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.audit_events_node_key_envelope_oversized_648_idx') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 648 requires the exact verified 647 release head' USING ERRCODE='P6480';
    END IF;
END;
$migration_648_up$;

-- The node list and detail mark a node "旧配置仍生效"
-- from the newest edge_publication.key_envelope_oversized event of each
-- (configuration scope, node) (nodepresence attachStaleConfigurations).
-- Without this index a node with no such event scanned every
-- audit event of the scope. The key follows the lookup: node, scope, then the
-- newest first.
CREATE INDEX audit_events_node_key_envelope_oversized_648_idx
    ON audit_events (resource_id, scope_id, occurred_at DESC, stream_position DESC)
    WHERE action = 'edge_publication.key_envelope_oversized' AND resource_type = 'node';
