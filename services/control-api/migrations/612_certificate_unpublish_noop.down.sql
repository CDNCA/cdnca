-- 612 回退：恢复 120 的结果形状约束、去掉 noop_reason。
-- 状态事实只追加：已有 no-op 结束的解绑（succeeded 且无 rollout）在 120 约束下不成立，拒绝回滚。
LOCK TABLE schema_migrations, certificate_publication_intent_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_612_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 612 OR
       (SELECT max(version) FROM schema_migrations) <> 612 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=612 AND
        migration_id='612_certificate_unpublish_noop' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 612 down requires the exact verified migration head' USING ERRCODE='P6121';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_publication_intent_state_facts WHERE noop_reason IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 612 rollback would drop certificate unpublications completed without a rollout'
            USING ERRCODE='P6122';
    END IF;
END;
$migration_612_down$;

DROP TRIGGER certificate_publication_noop_validate_612 ON certificate_publication_intent_state_facts;
DROP FUNCTION validate_certificate_publication_noop_612();

ALTER TABLE certificate_publication_intent_state_facts
    DROP CONSTRAINT certificate_publication_result_shape_612_check,
    ADD CONSTRAINT certificate_publication_result_shape_120_check CHECK (
        (state='succeeded' AND publication_id IS NOT NULL AND publication_revision>0 AND
         config_version_id IS NOT NULL AND rollout_id IS NOT NULL AND rollout_revision>0) OR
        (state<>'succeeded' AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL)
    ),
    DROP COLUMN noop_reason;
