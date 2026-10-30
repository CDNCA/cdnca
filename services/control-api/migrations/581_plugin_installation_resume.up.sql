-- 581（fix-plugresume 占位 601，merge-p22 按集成头连号改为 581，前驱钉 580）：插件主动暂停的对称恢复（报告 B，DEV-PLUG-01/F5）。
-- 租户主动暂停（disable）后只能升级或卸载，不能恢复使用。新增 resume 动作：
--   - head 触发器放开 disabled→enabled，要求与暂停对称：验证、版本、摘要、权限范围、LKG 不变，身份代际 +1；
--   - 收据 action/result 增加 resume/resumed（恢复不带原因）。
-- 只能恢复本主控自己的暂停：控制面写入前读授权端签名快照（paused_by=installation），授权端 lifecycle enable 再复核
-- 同一条件；平台暂停（运营/下架/安全公告）不能在这里恢复。1.0.35 全新安装，不涉及旧数据。
-- 前驱：580_analytics_log_export_owner（merge-p22 改号）。
LOCK TABLE schema_migrations, plugin_installation_heads, plugin_installation_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_581_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 580 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 580 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=580 AND
        migration_id='580_analytics_log_export_owner' AND
        checksum_sha256='c784eea1457d4d3638fea1f67d7ae5e28a7ff270a0e1daa6cfadc4f510ef22f3' AND
        down_checksum_sha256='b76f75bbaf1f76773efc831d94e75deee31fc379d080fd6bcf99e51c9bb3087e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid='plugin_installation_receipts'::regclass AND conname='plugin_installation_receipts_action_check'
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid='plugin_installation_receipts'::regclass AND conname='plugin_installation_receipts_result_check'
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger
        WHERE tgrelid='plugin_installation_heads'::regclass AND tgname='plugin_installation_heads_transition_145'
       ) THEN
        RAISE EXCEPTION 'migration 581 requires the exact verified 580 release head' USING ERRCODE='P5810';
    END IF;
END;
$migration_581_up$;

ALTER TABLE plugin_installation_receipts
    DROP CONSTRAINT plugin_installation_receipts_action_check,
    ADD CONSTRAINT plugin_installation_receipts_action_check
        CHECK (action IN ('confirm','upgrade','disable','resume','uninstall')),
    DROP CONSTRAINT plugin_installation_receipts_result_check,
    ADD CONSTRAINT plugin_installation_receipts_result_check
        CHECK (result IN ('installed','upgrade_applied','upgrade_failed_lkg_preserved','disabled','resumed','uninstalled')),
    ADD CONSTRAINT plugin_installation_receipts_resume_581_check
        CHECK ((action = 'resume') = (result = 'resumed') AND (action <> 'resume' OR reason IS NULL));

CREATE FUNCTION validate_plugin_installation_head_581()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.authorization_id IS DISTINCT FROM OLD.authorization_id OR
       NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
       NEW.plugin_id IS DISTINCT FROM OLD.plugin_id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.revision <> OLD.revision + 1 OR NEW.identity_generation < OLD.identity_generation OR
       NEW.identity_generation > OLD.identity_generation + 1 OR NEW.updated_at < OLD.updated_at OR
       (OLD.status = 'uninstalled') OR
       (OLD.status = 'disabled' AND NEW.status NOT IN ('disabled','enabled','uninstalled')) OR
       (OLD.status = 'enabled' AND NEW.status NOT IN ('enabled','disabled','uninstalled')) THEN
        RAISE EXCEPTION 'invalid plugin installation head transition' USING ERRCODE = 'P1451';
    END IF;
    -- Resume is the mirror of disable: the same verified authorization, only the runtime identity rotates.
    IF OLD.status = 'disabled' AND NEW.status = 'enabled' AND (
       NEW.verification_id IS DISTINCT FROM OLD.verification_id OR NEW.plugin_version IS DISTINCT FROM OLD.plugin_version OR
       NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256 OR
       NEW.configuration_schema_sha256 IS DISTINCT FROM OLD.configuration_schema_sha256 OR
       NEW.manifest_scopes IS DISTINCT FROM OLD.manifest_scopes OR
       NEW.approved_scopes IS DISTINCT FROM OLD.approved_scopes OR
       NEW.sensitive_scopes IS DISTINCT FROM OLD.sensitive_scopes OR
       NEW.lkg_verification_id IS DISTINCT FROM OLD.lkg_verification_id OR
       NEW.lkg_version IS DISTINCT FROM OLD.lkg_version OR
       NEW.identity_generation <> OLD.identity_generation + 1) THEN
        RAISE EXCEPTION 'plugin installation resume changed the paused authorization' USING ERRCODE = 'P5811';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER plugin_installation_heads_transition_145 ON plugin_installation_heads;
CREATE TRIGGER plugin_installation_heads_transition_581
BEFORE UPDATE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_head_581();
