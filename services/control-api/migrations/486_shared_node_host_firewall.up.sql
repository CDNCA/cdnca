-- 486（r136 p0a-firewall，Codex A08；调度预留 487，集成头 484 且加载器拒绝跳号，本地按 486 落，合入时按集成头改号并重钉前驱）：共享平台节点不再接收租户宿主防火墙规则。
-- 租户宿主规则只投到该租户自己的节点（nodes.scope_id = 租户 scope）；
-- 本迁移终结已排队、尚未回执的投到别人节点的租户宿主命令与发布，节点侧
-- Agent 在会话握手拿到节点归属后自行清掉已生效的这类规则（owner.go）。
LOCK TABLE schema_migrations, firewall_command_outbox, global_firewall_publication_outbox,
    global_firewall_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_486_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 485 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 485 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=485 AND
        migration_id='485_site_origin_route_endpoint_host' AND
        checksum_sha256='c64d5358608d5c625f6a1cd56ca5e23b9165389f73f3e0ebd9b9e20cabd8ebec' AND
        down_checksum_sha256='c6809a2fd482ecc8dd2c36c4b6cb937f226aee59c78a442181b7ca555321bbed' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 486 requires the exact verified 485 release head' USING ERRCODE='P4860';
    END IF;
END;
$migration_486_up$;

-- 0. 134 起 global 命令的外键 (tenant_scope_id,policy_id,policy_kind) 指向
--    security_policies，而该表 kind 只允许 waf/cc/acl：任何 global 命令都插不进
--    来（独占节点也投不出去）。拆成两条：非 global 指 security_policies，
--    global 指 global_firewall_policies。MATCH SIMPLE 下另一种的列为 NULL 时跳过。
ALTER TABLE firewall_command_outbox
    DROP CONSTRAINT firewall_command_outbox_tenant_policy_kind_fkey,
    ADD COLUMN security_policy_kind text GENERATED ALWAYS AS (CASE WHEN policy_kind<>'global' THEN policy_kind END) STORED,
    ADD COLUMN global_policy_id uuid GENERATED ALWAYS AS (CASE WHEN policy_kind='global' THEN policy_id END) STORED,
    ADD CONSTRAINT firewall_command_outbox_security_policy_486_fkey
        FOREIGN KEY(tenant_scope_id,policy_id,security_policy_kind) REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT,
    ADD CONSTRAINT firewall_command_outbox_global_policy_486_fkey
        FOREIGN KEY(tenant_scope_id,global_policy_id) REFERENCES global_firewall_policies(tenant_scope_id,id) ON DELETE RESTRICT;

-- 1. 排队中或已发出未回执的、投到非本 scope 节点的 global 命令：终结为 failed。
--    published 行直接 published->failed（111 守卫允许），回执晚到时 dispatch
--    按 failed 行丢弃。
UPDATE firewall_command_outbox command
SET state='failed', available_at=now(), published_at=CASE WHEN command.state='published' THEN command.published_at END,
    last_error='shared_node_host_firewall_unsupported', updated_at=now()
WHERE command.policy_kind='global' AND command.state IN ('pending','retryable','published')
  AND NOT EXISTS (SELECT 1 FROM nodes owner WHERE owner.id=command.node_id AND owner.scope_id=command.tenant_scope_id);

-- 2. 发布：所有命令都已终结的 projected 发布按 dispatch 的结算规则收口；
--    该 scope 没有自有节点的 pending/retryable 发布直接 projected->failed。
WITH settled AS (
    SELECT publication.id, publication.operation,
           count(command.id) AS total,
           count(command.id) FILTER (WHERE command.state IN ('acked','failed')) AS terminal,
           count(command.id) FILTER (WHERE command.terminal_state='applied') AS applied,
           count(command.id) FILTER (WHERE command.terminal_state='rolled_back') AS rolled_back
    FROM global_firewall_publication_outbox publication
    JOIN firewall_command_outbox command ON command.publication_id=publication.id AND command.policy_kind='global'
    WHERE publication.state='projected'
    GROUP BY publication.id, publication.operation
), outcome AS (
    SELECT id, CASE
        WHEN operation='apply' AND applied=total THEN 'active'
        WHEN operation='recover' AND rolled_back=total THEN 'rolled_back'
        WHEN applied>0 OR rolled_back>0 THEN 'partial'
        ELSE 'failed' END AS state
    FROM settled WHERE total>0 AND terminal=total
)
UPDATE global_firewall_publication_outbox publication
SET state=outcome.state, updated_at=now(),
    last_error=CASE WHEN outcome.state IN ('active','rolled_back') THEN NULL ELSE 'shared_node_host_firewall_unsupported' END
FROM outcome WHERE publication.id=outcome.id;

UPDATE global_firewall_publication_outbox publication
SET state='projected', projected_at=now(), updated_at=now()
WHERE publication.state IN ('pending','retryable') AND NOT EXISTS (
    SELECT 1 FROM nodes owner WHERE owner.scope_id=publication.tenant_scope_id AND owner.admin_state='active');
UPDATE global_firewall_publication_outbox publication
SET state='failed', last_error='shared_node_host_firewall_unsupported', updated_at=now()
WHERE publication.state='projected' AND NOT EXISTS (
    SELECT 1 FROM firewall_command_outbox command WHERE command.publication_id=publication.id)
  AND NOT EXISTS (
    SELECT 1 FROM nodes owner WHERE owner.scope_id=publication.tenant_scope_id AND owner.admin_state='active');

-- 3. 当前策略的部署状态跟随它当前修订的发布结果。
UPDATE global_firewall_policies policy
SET deployment_state=publication.state, updated_at=now()
FROM global_firewall_publication_outbox publication
WHERE publication.tenant_scope_id=policy.tenant_scope_id AND publication.policy_id=policy.id
  AND publication.revision=policy.revision AND publication.state IN ('failed','partial')
  AND policy.deployment_state IN ('pending','canary','partial');
