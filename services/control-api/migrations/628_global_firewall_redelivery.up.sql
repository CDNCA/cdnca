-- 628（前驱 627 node_deployment_host_replacements）：全局防火墙按节点补发。
-- 全局防火墙命令只在策略发布/恢复时按当时拥有的节点投影一次（publication_id,node_id,site_id 唯一），
-- 之后新加入、同 ID 重装、恢复上线的节点没有路径再拿到当前生效的策略。补发命令沿用当前生效发布的
-- publication_id（134 绑定触发器要求命令的文档摘要与发布一致），用 delivery 区分：0 是发布时的投影，
-- >0 是第几次按节点补发（firewallcontrol.Redeliverer 写）。dispatch 结算发布只数 delivery=0 的命令，
-- 补发命令的回执不改变发布与策略的部署状态。
LOCK TABLE schema_migrations, firewall_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_628_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 627 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 627 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=627 AND
        migration_id='627_node_deployment_host_replacements' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='firewall_command_outbox' AND column_name='delivery'
       ) THEN
        RAISE EXCEPTION 'migration 628 requires the exact verified 627 release head' USING ERRCODE='P6280';
    END IF;
END;
$migration_628_up$;

ALTER TABLE firewall_command_outbox
    ADD COLUMN delivery integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT firewall_command_outbox_delivery_628_check CHECK(delivery>=0 AND (delivery=0 OR policy_kind='global')),
    DROP CONSTRAINT firewall_command_outbox_publication_node_site_key,
    ADD CONSTRAINT firewall_command_outbox_publication_node_site_delivery_628_key UNIQUE(publication_id,node_id,site_id,delivery);

-- 补发扫描与投影的“在途补发”判定按 (租户, 策略) 查未终结的补发命令。
CREATE INDEX firewall_command_outbox_redelivery_628_idx
    ON firewall_command_outbox(tenant_scope_id,policy_id,created_at) WHERE delivery>0 AND state IN ('pending','retryable','published');

-- delivery 是命令身份的一部分（134 的身份守卫按固定列比较，不含新列）。
CREATE FUNCTION protect_firewall_command_outbox_delivery_628()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.delivery IS DISTINCT FROM OLD.delivery THEN
        RAISE EXCEPTION 'firewall command outbox delivery is immutable' USING ERRCODE='P6281';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_delivery_628
BEFORE UPDATE ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION protect_firewall_command_outbox_delivery_628();
