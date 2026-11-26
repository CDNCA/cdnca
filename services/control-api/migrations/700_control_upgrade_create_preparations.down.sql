-- 700 回退：删除节点升级创建准备记录表。已落库的计划与 096 的创建意图不受影响；仍在准备中或失败的准备随表删除，
-- 699 及更早版本的控制台用同一个 Idempotency-Key 重提创建时在请求内续跑对应意图。
LOCK TABLE schema_migrations, control_upgrade_grant_intents_096 IN ACCESS EXCLUSIVE MODE;

DO $migration_700_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 700 OR
       (SELECT max(version) FROM schema_migrations) <> 700 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=700 AND
        migration_id='700_control_upgrade_create_preparations' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 700 down requires the exact verified migration head' USING ERRCODE='P7004';
    END IF;
END;
$migration_700_down$;

DROP TABLE control_upgrade_create_preparations;
DROP FUNCTION validate_control_upgrade_create_preparation_700();
