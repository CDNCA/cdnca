LOCK TABLE schema_migrations, agent_gateways IN ACCESS EXCLUSIVE MODE;

DO $migration_449_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 448 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 448 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=448 AND
        migration_id='448_agent_gateway_settings' AND
        checksum_sha256='c474df5e04ff73f9b95d1c6545aaa1019750ff934f0f61d6fba5d9085222fcef' AND
        down_checksum_sha256='904abf00f6c180f56e633ca66f208a5ebbaa7bb02c49450e33b777d5206830ab' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='agent_gateways' AND column_name='disabled_at'
       ) THEN
        RAISE EXCEPTION 'migration 449 requires the exact verified 448 release head' USING ERRCODE='P4490';
    END IF;
END;
$migration_449_up$;

-- 449（r136 gw-impl5，原在占位 435 里原地追加；435 已作为 448 合入集成，merge-batch12 拆为新迁移）。
-- agent_gateways.disabled_at：停用时刻（ADR 0013 §5.2 停用驱逐）。停用后的宽限期内网关仍能为
-- 已连节点取授权/制品并经 GetGatewaySettings 得知自己已停用，不能再注册节点；宽限期过后完全拒绝。
-- 启用时清空。兼容基线 1.0.35：已停用网关以 updated_at 作为停用时刻。

ALTER TABLE agent_gateways ADD COLUMN disabled_at timestamptz;
UPDATE agent_gateways SET disabled_at=updated_at WHERE status='disabled';
ALTER TABLE agent_gateways ADD CONSTRAINT agent_gateways_disabled_449_ck CHECK ((status = 'disabled') = (disabled_at IS NOT NULL));
