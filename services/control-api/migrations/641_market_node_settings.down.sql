-- 641 回退：删除节点级设置的五张表。卖家已按订阅方快照建好的四层转发留在隐藏租户名下（是普通转发，
-- 照常运行，运营可在四层转发页删除）；买家文档随表删除，回退后订阅节点页不再显示节点设置入口。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_641_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 641 OR
       (SELECT max(version) FROM schema_migrations) <> 641 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=641 AND
        migration_id='641_market_node_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 641 down requires the exact verified migration head' USING ERRCODE='P6411';
    END IF;
END;
$migration_641_down$;

DROP TABLE market_node_settings_deliveries;
DROP TABLE market_node_settings;
DROP TABLE market_supply_node_disables;
DROP TABLE market_supply_node_streams;
DROP TABLE market_supply_node_settings;
