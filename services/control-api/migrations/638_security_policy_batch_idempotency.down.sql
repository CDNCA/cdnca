-- 638 回退：删除批次级幂等表。回退后批次接口回到只有逐项幂等（同键异体不再整批 409）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_638_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 638 OR
       (SELECT max(version) FROM schema_migrations) <> 638 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=638 AND
        migration_id='638_security_policy_batch_idempotency' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 638 down requires the exact verified migration head' USING ERRCODE='P6381';
    END IF;
END;
$migration_638_down$;

DROP TABLE security_policy_batch_write_requests;
