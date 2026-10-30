-- 589 回滚：tls_trust 去掉 'none'。已有选了"不校验源站证书"的回源池时拒绝回滚（不静默改成校验，否则自签源站会回源失败）。
LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_589_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 589 OR
       (SELECT max(version) FROM schema_migrations) <> 589 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=589 AND
        migration_id='589_site_origin_tls_no_verify' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 589 down requires the exact verified migration head' USING ERRCODE='P5891';
    END IF;
    IF EXISTS (SELECT 1 FROM site_origin_pools WHERE tls_trust = 'none') THEN
        RAISE EXCEPTION 'migration 589 down refuses origin pools that do not verify the origin certificate' USING ERRCODE='P5892';
    END IF;
END;
$migration_589_down$;

ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_tls_trust_check,
    ADD CONSTRAINT site_origin_pools_tls_trust_check CHECK (tls_trust IN ('system', 'custom'));
