-- 669 回退：恢复回滚判定改回只认租户 scope 的节点。已写入的恢复回滚行不受影响（触发器只在插入时校验）。
-- 删除恢复后重新发布的去重表；在途候选补占推进的 source revision 不回退（版本号只增不减）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_recovery_rollouts IN SHARE ROW EXCLUSIVE MODE;

DO $migration_669_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 669 OR
       (SELECT max(version) FROM schema_migrations) <> 669 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=669 AND
        migration_id='669_security_activation_recovery_platform_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 669 down requires the exact verified migration head' USING ERRCODE='P6691';
    END IF;
END;
$migration_669_down$;

DO $migration_669_down_function$
DECLARE
    needle constant text := 'AND node.scope_id=NEW.tenant_scope_id';
    value constant text := 'AND (node.scope_id=NEW.tenant_scope_id OR EXISTS (SELECT 1 FROM access_scopes node_scope WHERE node_scope.id=node.scope_id AND node_scope.kind=''platform''))';
    definition text;
BEGIN
    SELECT pg_get_functiondef('validate_security_policy_activation_recovery_rollout_088()'::regprocedure) INTO definition;
    IF (length(definition) - length(replace(definition, value, ''))) / length(value) <> 1 THEN
        RAISE EXCEPTION 'migration 669 down cannot find the recovery node scope check' USING ERRCODE='P6691';
    END IF;
    EXECUTE replace(definition, value, needle);
END;
$migration_669_down_function$;

DROP TABLE security_activation_recovery_republications_669;
