-- 566（fix-cfl-a2，竞品 10-27 第 1 条“清理旧数据”；占位，合入时由主会话改号与改钉前驱，前驱暂钉集成头 554_node_bandwidth_alerts）。
-- 系统设置“清缓存、解锁IP历史记录”（cleanup_cache_days，默认 30 天，0 = 永久保留）此前没有任何执行者。
-- 本迁移只允许专用清理角色 cdnca_retention_cleanup（320）删除：
--   * 已结束（succeeded/partial_failed/failed/cancelled）、completed_at 早于期限、且没有未完成命令的缓存操作及其全部子表；
--   * 已解除且 released_at 早于期限、或未解除但 banned_until 早于期限（已过期）的 IP 封禁记录。
--     已解除的记录还要在 7 天释放下发窗口（libs/edgeconfig/securityban ReleaseWindow）之外，节点才收得到解除。
-- 其他角色的删除保护不变；每批删除由 worker 写审计（system_cleanup.retention.delete）。
LOCK TABLE schema_migrations, cache_operations, cache_operation_commands, cache_operation_targets,
    cache_operation_nodes, cache_operation_node_targets, cache_operation_node_attempts,
    cache_operation_target_results, cache_operation_cancel_deliveries, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_566_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 565 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 565 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=565 AND
        migration_id='565_site_supply_receipt_reconcile' AND
        checksum_sha256='7f0725a8f86a752f6103160adc6e90f001d88e5f7055fcc1c08582a2dfc66bd2' AND
        down_checksum_sha256='b687c6b4787cc347bb28c238ddfc27f1cc91136c363bccde8f69c56535fe886c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.retention_cleanup_cutoff_566(text)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 566 requires the exact verified 565 release head' USING ERRCODE='P5660';
    END IF;
END;
$migration_566_up$;

-- 可保留的最早时刻：now() 减去 cleanup_cache_days（各平台 scope 取最大值；未设置按默认 30；0 返回 NULL 即不清理）。
-- 设置值非法时报错（不清理）。
DO $migration_566_cutoff$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.retention_cleanup_cutoff_566(setting text) RETURNS timestamptz
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        DECLARE
            days integer;
        BEGIN
            IF setting <> 'cleanup_cache_days' THEN
                RAISE EXCEPTION 'unknown retention setting %%', setting USING ERRCODE='P5662';
            END IF;
            SELECT max((settings->>setting)::integer) INTO days FROM %I.platform_system_cleanup_settings
                WHERE settings ? setting;
            days := COALESCE(days, 30);
            IF days < 0 OR days > 3650 THEN
                RAISE EXCEPTION 'retention setting %% is out of range', setting USING ERRCODE='P5662';
            END IF;
            IF days = 0 THEN
                RETURN NULL;
            END IF;
            RETURN transaction_timestamp() - make_interval(days => days);
        END;
        $body$;
    $ddl$, current_schema(), current_schema());
END;
$migration_566_cutoff$;

-- 缓存操作可被清理：已结束、结束时间早于期限、没有未完成的取消/重试命令。
CREATE FUNCTION cache_operation_retention_expired_566(target uuid) RETURNS boolean
LANGUAGE sql STABLE AS $function$
    SELECT EXISTS (
        SELECT 1 FROM cache_operations operation
        WHERE operation.id = target
          AND operation.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')
          AND operation.completed_at < retention_cleanup_cutoff_566('cleanup_cache_days')
          AND NOT EXISTS (SELECT 1 FROM cache_operation_commands command
              WHERE command.operation_id = operation.id AND command.completed_at IS NULL)
    )
$function$;

-- 清理角色删除缓存操作及其子表时逐行复核（子表按所属操作判断）。
CREATE FUNCTION guard_retention_delete_cache_566()
RETURNS trigger LANGUAGE plpgsql AS $function$
DECLARE
    operation uuid;
BEGIN
    IF TG_TABLE_NAME = 'cache_operations' THEN
        operation := OLD.id;
    ELSE
        operation := OLD.operation_id;
    END IF;
    IF NOT cache_operation_retention_expired_566(operation) THEN
        RAISE EXCEPTION 'cache operation is within retention' USING ERRCODE='P5663';
    END IF;
    RETURN OLD;
END;
$function$;
-- 原有删除保护改为对清理角色之外的角色生效；清理角色改由上面的守卫逐行复核。
-- worker 按子表到父表的顺序逐表显式删除（不依赖级联：级联以表属主身份执行，绕过 current_user 判断）。
-- 清理角色读不到 nodes，所以带 node_purge_permits 的条件先判 current_user（同 332）。
DROP TRIGGER cache_operations_protected ON cache_operations;
CREATE TRIGGER cache_operations_protected BEFORE UPDATE ON cache_operations
    FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_transition();
CREATE TRIGGER cache_operations_protected_del_566 BEFORE DELETE ON cache_operations FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION protect_cache_operation_transition();

DROP TRIGGER cache_operation_commands_protected ON cache_operation_commands;
CREATE TRIGGER cache_operation_commands_protected BEFORE INSERT OR UPDATE ON cache_operation_commands
    FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_command();
CREATE TRIGGER cache_operation_commands_protected_del_566 BEFORE DELETE ON cache_operation_commands FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION protect_cache_operation_command();

DROP TRIGGER cache_operation_targets_append_only ON cache_operation_targets;
CREATE TRIGGER cache_operation_targets_append_only BEFORE UPDATE ON cache_operation_targets
    FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();
CREATE TRIGGER cache_operation_targets_append_only_del_566 BEFORE DELETE ON cache_operation_targets FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION prevent_cache_append_only_mutation();

DROP TRIGGER cache_operation_nodes_no_delete ON cache_operation_nodes;
CREATE TRIGGER cache_operation_nodes_no_delete BEFORE DELETE ON cache_operation_nodes FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION prevent_cache_projection_delete();
DROP TRIGGER cache_operation_nodes_integrity_del ON cache_operation_nodes;
CREATE CONSTRAINT TRIGGER cache_operation_nodes_integrity_del AFTER DELETE ON cache_operation_nodes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION validate_cache_operation_integrity();

DROP TRIGGER cache_operation_node_targets_no_delete ON cache_operation_node_targets;
CREATE TRIGGER cache_operation_node_targets_no_delete BEFORE DELETE ON cache_operation_node_targets FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION prevent_cache_projection_delete();
DROP TRIGGER cache_operation_node_targets_integrity_del ON cache_operation_node_targets;
CREATE CONSTRAINT TRIGGER cache_operation_node_targets_integrity_del AFTER DELETE ON cache_operation_node_targets
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION validate_cache_operation_integrity();

DROP TRIGGER cache_operation_node_attempts_protected_del ON cache_operation_node_attempts;
CREATE TRIGGER cache_operation_node_attempts_protected_del BEFORE DELETE ON cache_operation_node_attempts FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION protect_cache_operation_attempt();
DROP TRIGGER cache_operation_node_attempts_integrity_del ON cache_operation_node_attempts;
CREATE CONSTRAINT TRIGGER cache_operation_node_attempts_integrity_del AFTER DELETE ON cache_operation_node_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION validate_cache_operation_integrity();

DROP TRIGGER cache_operation_target_results_append_only_del ON cache_operation_target_results;
CREATE TRIGGER cache_operation_target_results_append_only_del BEFORE DELETE ON cache_operation_target_results FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION prevent_cache_append_only_mutation();
DROP TRIGGER cache_operation_target_results_integrity_del ON cache_operation_target_results;
CREATE CONSTRAINT TRIGGER cache_operation_target_results_integrity_del AFTER DELETE ON cache_operation_target_results
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION validate_cache_operation_integrity();

DO $migration_566_cache_guards$
DECLARE
    name text;
BEGIN
    FOREACH name IN ARRAY ARRAY['cache_operations', 'cache_operation_commands', 'cache_operation_targets',
        'cache_operation_nodes', 'cache_operation_node_targets', 'cache_operation_node_attempts',
        'cache_operation_target_results', 'cache_operation_cancel_deliveries'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %I FOR EACH ROW
            WHEN (current_user = %L) EXECUTE FUNCTION guard_retention_delete_cache_566()',
            name || '_retention_566', name, 'cdnca_retention_cleanup');
    END LOOP;
END;
$migration_566_cache_guards$;

-- IP 封禁记录：表上原本没有删除路径（应用角色无 DELETE 权限）。清理角色只能删：
-- 已解除、解除时间早于期限且已出 7 天释放下发窗口的；未解除但封禁到期时间早于期限的。
CREATE FUNCTION guard_retention_delete_security_ban_566()
RETURNS trigger LANGUAGE plpgsql AS $function$
DECLARE
    cutoff timestamptz := retention_cleanup_cutoff_566('cleanup_cache_days');
BEGIN
    -- CASE 必须加括号：PL/pgSQL 的 IF 会把 CASE 里的第一个 THEN 当成 IF 的 THEN。
    IF cutoff IS NULL OR NOT (CASE WHEN OLD.released_at IS NOT NULL
        THEN OLD.released_at < least(cutoff, transaction_timestamp() - interval '7 days')
        ELSE OLD.banned_until < cutoff END) THEN
        RAISE EXCEPTION 'security ban entry is within retention' USING ERRCODE='P5664';
    END IF;
    RETURN OLD;
END;
$function$;
CREATE TRIGGER security_ban_entries_retention_566 BEFORE DELETE ON security_ban_entries FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup') EXECUTE FUNCTION guard_retention_delete_security_ban_566();

-- worker 按完成时间挑选过期缓存操作。
CREATE INDEX cache_operations_retention_566_idx ON cache_operations (completed_at)
    WHERE state IN ('succeeded', 'partial_failed', 'failed', 'cancelled');
CREATE INDEX security_ban_entries_until_566_idx ON security_ban_entries (banned_until) WHERE released_at IS NULL;

DO $migration_566_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
        GRANT SELECT, DELETE ON cache_operations, cache_operation_commands, cache_operation_targets,
            cache_operation_nodes, cache_operation_node_targets, cache_operation_node_attempts,
            cache_operation_target_results, cache_operation_cancel_deliveries, security_ban_entries
            TO cdnca_retention_cleanup;
        GRANT EXECUTE ON FUNCTION retention_cleanup_cutoff_566(text) TO cdnca_retention_cleanup;
        GRANT EXECUTE ON FUNCTION cache_operation_retention_expired_566(uuid) TO cdnca_retention_cleanup;
    END IF;
END;
$migration_566_grants$;
