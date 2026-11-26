-- 685 回滚：去掉已消费注册证明的幂等键摘要索引。684 及更早版本不按邮箱找回，不读这个索引。
LOCK TABLE schema_migrations, account_registration_proofs_162 IN ACCESS EXCLUSIVE MODE;

DO $migration_685_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 685 OR
       (SELECT max(version) FROM schema_migrations) <> 685 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=685 AND
        migration_id='685_registration_proof_consumed_digest_index' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 685 down requires the exact verified migration head' USING ERRCODE='P6851';
    END IF;
END;
$migration_685_down$;

DROP INDEX account_registration_proofs_consumed_685;
