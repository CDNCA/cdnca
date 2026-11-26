-- 703 回退：删除源池版本列。702 及更早版本的计费桥改源站按网站修订号判断并发（CNAME 投影后首次改源站会 409）。
LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_703_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 703 OR
       (SELECT max(version) FROM schema_migrations) <> 703 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=703 AND
        migration_id='703_site_origin_pool_site_revision' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 703 down requires the exact verified migration head' USING ERRCODE='P7030';
    END IF;
END;
$migration_703_down$;

ALTER TABLE site_origin_pools DROP COLUMN site_revision;
