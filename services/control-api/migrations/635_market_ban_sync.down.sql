-- 635 回退：删除三张表；叶子按买家快照写的名单行（source=market）一并删除——它们只是买家名单的副本，原件在买家，
-- 回退后叶子不再接收买家名单，分发器下一轮就不再把它们发给节点。source 约束恢复 415 原文。
LOCK TABLE schema_migrations, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_635_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 635 OR
       (SELECT max(version) FROM schema_migrations) <> 635 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=635 AND
        migration_id='635_market_ban_sync' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 635 down requires the exact verified migration head' USING ERRCODE='P6351';
    END IF;
END;
$migration_635_down$;

DROP TABLE site_supply_ban_deliveries;
DROP TABLE market_supply_ban_sites;
DROP TABLE market_supply_ban_refs;
DELETE FROM security_ban_entries WHERE source = 'market';
ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_source_635;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_source_415
    CHECK (source IN ('waf', 'cc', 'manual', 'autodefense'));
