-- 581 回滚：恢复 145 的 head 转移触发器与收据 action/result 约束。已有恢复收据时拒绝回滚（收据只追加，不静默丢弃事实）。
LOCK TABLE schema_migrations, plugin_installation_heads, plugin_installation_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_581_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 581 OR
       (SELECT max(version) FROM schema_migrations) <> 581 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=581 AND
        migration_id='581_plugin_installation_resume' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 581 down requires the exact verified migration head' USING ERRCODE='P5812';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_installation_receipts WHERE action='resume') THEN
        RAISE EXCEPTION 'migration 581 down refuses recorded plugin resume receipts' USING ERRCODE='P5813';
    END IF;
END;
$migration_581_down$;

DROP TRIGGER plugin_installation_heads_transition_581 ON plugin_installation_heads;
DROP FUNCTION validate_plugin_installation_head_581();
CREATE TRIGGER plugin_installation_heads_transition_145
BEFORE UPDATE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_head_145();

ALTER TABLE plugin_installation_receipts
    DROP CONSTRAINT plugin_installation_receipts_resume_581_check,
    DROP CONSTRAINT plugin_installation_receipts_result_check,
    ADD CONSTRAINT plugin_installation_receipts_result_check
        CHECK (result IN ('installed','upgrade_applied','upgrade_failed_lkg_preserved','disabled','uninstalled')),
    DROP CONSTRAINT plugin_installation_receipts_action_check,
    ADD CONSTRAINT plugin_installation_receipts_action_check
        CHECK (action IN ('confirm','upgrade','disable','uninstall'));
