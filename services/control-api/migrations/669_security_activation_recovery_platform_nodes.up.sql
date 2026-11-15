-- 669（安全激活恢复回滚放行平台 scope 共享节点，候选认领即占用 source revision）；前驱 668_system_settings_secret_fields。
-- 安全激活恢复回滚的 queued 判定（095）要求每个节点 nodes.scope_id 等于租户 scope。287 多租户共享节点后
-- 节点都在平台 scope，这一条对共享节点永远不成立：失败/取消/过期的候选写不进恢复回滚（P8802），晋升冲突时
-- 候选卡在 healthy 直到过期，过期后 worker 退出拖垮主控。改为与下发部署相同的规则
-- （edgedeployment.createNodeDeployment）：节点属于租户 scope，或属于平台 scope。节点仍须在该租户 scope
-- 有 node_config_state 行（同一判定里已关联）。只改这一处条件，其余身份校验不变。
--
-- 同批：候选认领预留的 source revision 改为真正占用。原来认领只记
-- candidate_source_revision=N+1、scope 停在 N，晋升时才 CAS 到 N+1；期间任何改动把 scope 推到 N+1 并以
-- N+1 发布，节点已用候选 root 接受过 N+1，拒收后者（"source revision N+1 was accepted with another
-- root"），改动静默不生效。现在认领即把 scope 推到 N+1，之后的改动从
-- N+2 起；晋升只确认 scope 仍停在 N+1。本迁移：
--   1. 在途候选（claimed/canary/expanding/healthy）按新规则补占：scope 停在 N（未撞号）推到 N+1；
--      scope 已在 N+1（已被别的写入撞号）也推一格，使其晋升 CAS 失败、走恢复，不会把撞号版本当成候选晋升。
--   2. security_activation_recovery_republications_669：候选恢复后（或撞号存量）由系统重新发布一次，
--      每个候选最多一次（internal/securityactivation/revision.go）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_recovery_rollouts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE edge_configuration_scopes, security_policy_activation_candidates IN SHARE ROW EXCLUSIVE MODE;

DO $migration_669_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 668 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 668 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=668 AND
        migration_id='668_system_settings_secret_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 669 requires the exact verified 668 release head' USING ERRCODE='P6690';
    END IF;
END;
$migration_669_up$;

DO $migration_669_function$
DECLARE
    needle constant text := 'AND node.scope_id=NEW.tenant_scope_id';
    value constant text := 'AND (node.scope_id=NEW.tenant_scope_id OR EXISTS (SELECT 1 FROM access_scopes node_scope WHERE node_scope.id=node.scope_id AND node_scope.kind=''platform''))';
    definition text;
BEGIN
    SELECT pg_get_functiondef('validate_security_policy_activation_recovery_rollout_088()'::regprocedure) INTO definition;
    IF (length(definition) - length(replace(definition, needle, ''))) / length(needle) <> 1 OR
       strpos(definition, 'node_scope.kind') <> 0 THEN
        RAISE EXCEPTION 'migration 669 cannot find the recovery node scope check' USING ERRCODE='P6690';
    END IF;
    EXECUTE replace(definition, needle, value);
END;
$migration_669_function$;

UPDATE edge_configuration_scopes scope SET source_revision=scope.source_revision+1, updated_at=clock_timestamp()
WHERE EXISTS (
    SELECT 1 FROM security_policy_activation_candidates candidate
    WHERE candidate.tenant_scope_id=scope.scope_id
      AND candidate.candidate_status IN ('claimed','canary','expanding','healthy')
      AND candidate.candidate_source_revision IN (scope.source_revision, scope.source_revision+1)
);

CREATE TABLE security_activation_recovery_republications_669 (
    candidate_id uuid PRIMARY KEY REFERENCES security_policy_activation_candidates(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 1),
    created_at timestamptz NOT NULL
);

REVOKE ALL ON security_activation_recovery_republications_669 FROM PUBLIC;
GRANT SELECT, INSERT ON security_activation_recovery_republications_669 TO cdnca_control_app, cdnca_control_runtime;
