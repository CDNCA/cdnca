-- 637 回退：删除整机样本表与 exclusive 列。样本只是卖方指标的短期副本（24 小时），exclusive 下一轮同步前
-- 由市场重新给出；回退后买方页面对独享节点退回 §8 的"本主控站点流量"视图。
LOCK TABLE schema_migrations, market_subscribed_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_637_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 637 OR
       (SELECT max(version) FROM schema_migrations) <> 637 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=637 AND
        migration_id='637_market_exclusive_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 637 down requires the exact verified migration head' USING ERRCODE='P6371';
    END IF;
END;
$migration_637_down$;

DROP TABLE market_subscribed_node_host_samples;
ALTER TABLE market_subscribed_nodes DROP COLUMN exclusive;
