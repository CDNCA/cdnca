-- 661 回退：删除按小时流量汇总表；月流量读取回到扫原始样本的旧算法前需先回退代码。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_661_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 661 OR
       (SELECT max(version) FROM schema_migrations) <> 661 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=661 AND migration_id='661_node_traffic_hourly' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 661 down requires the exact verified migration head' USING ERRCODE='P6611';
    END IF;
END;
$migration_661_down$;

DROP TABLE node_traffic_hourly;
