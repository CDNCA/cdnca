-- 642 回退：删除买方本机别名与备注。页面回到只显示原名。
LOCK TABLE schema_migrations, site_supplies, market_subscribed_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_642_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 642 OR
       (SELECT max(version) FROM schema_migrations) <> 642 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=642 AND
        migration_id='642_market_local_labels' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 642 down requires the exact verified migration head' USING ERRCODE='P6421';
    END IF;
END;
$migration_642_down$;

ALTER TABLE market_subscribed_nodes DROP CONSTRAINT market_subscribed_nodes_local_label_642_check;
ALTER TABLE market_subscribed_nodes DROP COLUMN local_note, DROP COLUMN local_alias;
ALTER TABLE site_supplies DROP CONSTRAINT site_supplies_local_label_642_check;
ALTER TABLE site_supplies DROP COLUMN local_note, DROP COLUMN local_alias;
