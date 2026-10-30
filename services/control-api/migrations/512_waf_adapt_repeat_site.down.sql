-- 回滚 512：站点灰区重复阈值回到节点常量（已设置的站点值随列删除）。
LOCK TABLE schema_migrations, waf_adapt_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_512_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 512 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=512 AND migration_id='512_waf_adapt_repeat_site'
       ) THEN
        RAISE EXCEPTION 'rollback of 512 requires 512_waf_adapt_repeat_site at the head' USING ERRCODE='P5121';
    END IF;
END;
$migration_512_down$;

ALTER TABLE waf_adapt_sites
    DROP CONSTRAINT waf_adapt_sites_repeat_pair_512,
    DROP COLUMN repeat_window,
    DROP COLUMN repeat_threshold;
