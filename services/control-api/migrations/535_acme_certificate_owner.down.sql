-- 535 回滚：只删归属规则函数。已回填/已记录的 ACME 证书所属用户是事实，按 276 不可变，保留。
LOCK TABLE schema_migrations, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_535_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 535 OR
       (SELECT max(version) FROM schema_migrations) <> 535 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=535 AND
        migration_id='535_acme_certificate_owner' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 535 down requires the exact verified migration head' USING ERRCODE='P5351';
    END IF;
END;
$migration_535_down$;

DROP FUNCTION resolve_certificate_order_owner_535(uuid, uuid);
