-- 702 回退：删除发布承载节点记录。701 及更早版本的停止 overlay 与节点设置重发按当前线路分组计算屏蔽集合。
LOCK TABLE schema_migrations, edge_publication_serving_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_702_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 702 OR
       (SELECT max(version) FROM schema_migrations) <> 702 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=702 AND
        migration_id='702_edge_publication_serving_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 702 down requires the exact verified migration head' USING ERRCODE='P7020';
    END IF;
END;
$migration_702_down$;

DROP TABLE edge_publication_serving_nodes;
DROP FUNCTION protect_edge_publication_serving_nodes_702();
