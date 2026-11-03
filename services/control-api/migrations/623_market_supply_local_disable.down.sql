-- 623 回退：删除本机停用标记与下发原因留痕。停用中的供给回退后恢复参与本机 DNS（与停用前一致）。
LOCK TABLE schema_migrations, site_supplies, site_supply_leaf_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_623_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 623 OR
       (SELECT max(version) FROM schema_migrations) <> 623 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=623 AND
        migration_id='623_market_supply_local_disable' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 623 down requires the exact verified migration head' USING ERRCODE='P6231';
    END IF;
END;
$migration_623_down$;

ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT site_supply_leaf_sites_blockers_623_check;
ALTER TABLE site_supply_leaf_sites DROP COLUMN blockers_revision, DROP COLUMN blockers;
ALTER TABLE site_supplies DROP CONSTRAINT site_supplies_local_disabled_623_check;
ALTER TABLE site_supplies DROP COLUMN local_disabled_at;
