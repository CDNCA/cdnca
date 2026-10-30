-- 566 回滚：恢复缓存操作表原有的删除保护（034/284），去掉清理角色的删除权限与守卫。已清理的历史不恢复。
LOCK TABLE schema_migrations, cache_operations, cache_operation_commands, cache_operation_targets,
    cache_operation_nodes, cache_operation_node_targets, cache_operation_node_attempts,
    cache_operation_target_results, cache_operation_cancel_deliveries, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_566_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 566 OR
       (SELECT max(version) FROM schema_migrations) <> 566 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=566 AND
        migration_id='566_cache_ban_history_retention' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 566 down requires the exact verified migration head' USING ERRCODE='P5661';
    END IF;
END;
$migration_566_down$;

DO $migration_566_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE SELECT, DELETE ON cache_operations, cache_operation_commands, cache_operation_targets,
            cache_operation_nodes, cache_operation_node_targets, cache_operation_node_attempts,
            cache_operation_target_results, cache_operation_cancel_deliveries, security_ban_entries
            FROM cdnca_retention_cleanup;
    END IF;
END;
$migration_566_revoke$;

DROP INDEX security_ban_entries_until_566_idx;
DROP INDEX cache_operations_retention_566_idx;
DROP TRIGGER security_ban_entries_retention_566 ON security_ban_entries;
DROP FUNCTION guard_retention_delete_security_ban_566();

DO $migration_566_cache_guards$
DECLARE
    name text;
BEGIN
    FOREACH name IN ARRAY ARRAY['cache_operations', 'cache_operation_commands', 'cache_operation_targets',
        'cache_operation_nodes', 'cache_operation_node_targets', 'cache_operation_node_attempts',
        'cache_operation_target_results', 'cache_operation_cancel_deliveries'] LOOP
        EXECUTE format('DROP TRIGGER %I ON %I', name || '_retention_566', name);
    END LOOP;
END;
$migration_566_cache_guards$;

DROP TRIGGER cache_operation_target_results_integrity_del ON cache_operation_target_results;
CREATE CONSTRAINT TRIGGER cache_operation_target_results_integrity_del AFTER DELETE ON cache_operation_target_results
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_target_results_append_only_del ON cache_operation_target_results;
CREATE TRIGGER cache_operation_target_results_append_only_del BEFORE DELETE ON cache_operation_target_results FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_append_only_mutation();

DROP TRIGGER cache_operation_node_attempts_integrity_del ON cache_operation_node_attempts;
CREATE CONSTRAINT TRIGGER cache_operation_node_attempts_integrity_del AFTER DELETE ON cache_operation_node_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_node_attempts_protected_del ON cache_operation_node_attempts;
CREATE TRIGGER cache_operation_node_attempts_protected_del BEFORE DELETE ON cache_operation_node_attempts FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_cache_operation_attempt();

DROP TRIGGER cache_operation_node_targets_integrity_del ON cache_operation_node_targets;
CREATE CONSTRAINT TRIGGER cache_operation_node_targets_integrity_del AFTER DELETE ON cache_operation_node_targets
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_node_targets_no_delete ON cache_operation_node_targets;
CREATE TRIGGER cache_operation_node_targets_no_delete BEFORE DELETE ON cache_operation_node_targets FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_projection_delete();

DROP TRIGGER cache_operation_nodes_integrity_del ON cache_operation_nodes;
CREATE CONSTRAINT TRIGGER cache_operation_nodes_integrity_del AFTER DELETE ON cache_operation_nodes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_nodes_no_delete ON cache_operation_nodes;
CREATE TRIGGER cache_operation_nodes_no_delete BEFORE DELETE ON cache_operation_nodes FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_projection_delete();

DROP TRIGGER cache_operation_targets_append_only_del_566 ON cache_operation_targets;
DROP TRIGGER cache_operation_targets_append_only ON cache_operation_targets;
CREATE TRIGGER cache_operation_targets_append_only BEFORE UPDATE OR DELETE ON cache_operation_targets
    FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();

DROP TRIGGER cache_operation_commands_protected_del_566 ON cache_operation_commands;
DROP TRIGGER cache_operation_commands_protected ON cache_operation_commands;
CREATE TRIGGER cache_operation_commands_protected BEFORE INSERT OR UPDATE OR DELETE ON cache_operation_commands
    FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_command();

DROP TRIGGER cache_operations_protected_del_566 ON cache_operations;
DROP TRIGGER cache_operations_protected ON cache_operations;
CREATE TRIGGER cache_operations_protected BEFORE UPDATE OR DELETE ON cache_operations
    FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_transition();

DROP FUNCTION guard_retention_delete_cache_566();
DROP FUNCTION cache_operation_retention_expired_566(uuid);
DROP FUNCTION retention_cleanup_cutoff_566(text);
