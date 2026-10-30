-- 563 回滚：跟随平台的站点按当时的平台默认模式写回为单独设置的模式，平台设置 default_mode 还原为 new_site_learning。
LOCK TABLE schema_migrations, autodefense_sites, autodefense_platform_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_563_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 563 OR
       (SELECT max(version) FROM schema_migrations) <> 563 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=563 AND
        migration_id='563_autodefense_follow_platform' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 563 down requires the exact verified migration head' USING ERRCODE='P5631';
    END IF;
END;
$migration_563_down$;

UPDATE autodefense_sites SET mode=COALESCE((SELECT p.settings->>'default_mode' FROM autodefense_platform_settings p), 'learning'),
    revision=revision+1
WHERE mode='follow';

UPDATE autodefense_platform_settings
SET settings = (settings - 'default_mode') || jsonb_build_object('new_site_learning', settings->>'default_mode' = 'learning')
WHERE settings ? 'default_mode';

ALTER TABLE autodefense_sites DROP CONSTRAINT autodefense_sites_mode_check;
ALTER TABLE autodefense_sites ADD CONSTRAINT autodefense_sites_mode_check
    CHECK (mode IN ('off', 'learning', 'observe', 'protect'));
