LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_536_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 536 OR
       (SELECT max(version) FROM schema_migrations) <> 536 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=536 AND
        migration_id='536_node_peer_probe_log' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 536 down requires the exact verified migration head' USING ERRCODE='P5361';
    END IF;
END;
$migration_536_down$;

-- 可用性日志只是观测记录（8 天滚动），回滚直接删除。
DROP TABLE node_peer_probe_results;
