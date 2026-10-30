-- 544 回滚：主控自己写的官方包平台行回到 inherit（454 的 system/waf-php-vpatch 仍为 enabled，
-- 544 之前只有它默认启用）。主控已替网站发布的挂载保留，网站页面显示“有未发布的变更”，
-- 站点下次发布时按回滚后的设置重新计算。
LOCK TABLE schema_migrations, rule_pack_enablements IN ACCESS EXCLUSIVE MODE;

DO $migration_544_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 544 OR
       (SELECT max(version) FROM schema_migrations) <> 544 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=544 AND
        migration_id='544_official_rule_packs_enabled' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 544 down requires the exact verified migration head' USING ERRCODE='P5441';
    END IF;
END;
$migration_544_down$;

UPDATE rule_pack_enablements SET state='inherit', updated_at=CURRENT_TIMESTAMP
    WHERE level='platform' AND rule_id IS NULL AND updated_by_user_id IS NULL AND state='enabled' AND
        pack_id <> 'system/waf-php-vpatch';
