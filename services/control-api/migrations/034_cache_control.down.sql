LOCK TABLE cache_policy_heads,
    cache_policy_revisions,
    cache_policy_write_requests,
    cache_operations,
    cache_operation_commands,
    cache_operation_targets,
    cache_operation_nodes,
    cache_operation_node_targets,
    cache_operation_node_attempts,
    cache_operation_target_results,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM cache_policy_heads) OR
       EXISTS (SELECT 1 FROM cache_policy_revisions) OR
       EXISTS (SELECT 1 FROM cache_policy_write_requests) OR
       EXISTS (SELECT 1 FROM cache_operations) OR
       EXISTS (SELECT 1 FROM cache_operation_commands) OR
       EXISTS (SELECT 1 FROM cache_operation_targets) OR
       EXISTS (SELECT 1 FROM cache_operation_nodes) OR
       EXISTS (SELECT 1 FROM cache_operation_node_targets) OR
       EXISTS (SELECT 1 FROM cache_operation_node_attempts) OR
       EXISTS (SELECT 1 FROM cache_operation_target_results) OR
       EXISTS (
           SELECT 1 FROM audit_events
           WHERE action = 'cache_policy.publish' OR action LIKE 'cache.operation.%'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'cache control facts exist; migration 034 cannot be reverted';
    END IF;
END;
$$;

DROP TRIGGER cache_operation_audit_integrity ON audit_events;
DROP TRIGGER cache_operation_commands_integrity ON cache_operation_commands;
DROP TRIGGER cache_operation_target_results_integrity ON cache_operation_target_results;
DROP TRIGGER cache_operation_node_attempts_integrity ON cache_operation_node_attempts;
DROP TRIGGER cache_operation_node_targets_integrity ON cache_operation_node_targets;
DROP TRIGGER cache_operation_nodes_integrity ON cache_operation_nodes;
DROP TRIGGER cache_operations_integrity ON cache_operations;
DROP FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_policy_audit_integrity ON audit_events;
DROP TRIGGER cache_policy_write_requests_integrity ON cache_policy_write_requests;
DROP TRIGGER cache_policy_revisions_integrity ON cache_policy_revisions;
DROP TRIGGER cache_policy_heads_integrity ON cache_policy_heads;
DROP FUNCTION validate_cache_policy_integrity();
DROP TRIGGER cache_operation_commands_complete ON cache_operation_commands;
DROP TRIGGER cache_policy_write_requests_complete ON cache_policy_write_requests;
DROP FUNCTION validate_cache_idempotency_completion();

DROP TRIGGER cache_operation_audit_no_truncate ON audit_events;
DROP TRIGGER cache_operation_target_results_no_truncate ON cache_operation_target_results;
DROP TRIGGER cache_operation_node_attempts_no_truncate ON cache_operation_node_attempts;
DROP TRIGGER cache_operation_node_targets_no_truncate ON cache_operation_node_targets;
DROP TRIGGER cache_operation_nodes_no_truncate ON cache_operation_nodes;
DROP TRIGGER cache_operation_targets_no_truncate ON cache_operation_targets;
DROP TRIGGER cache_operation_commands_no_truncate ON cache_operation_commands;
DROP TRIGGER cache_operations_no_truncate ON cache_operations;
DROP TRIGGER cache_policy_write_requests_no_truncate ON cache_policy_write_requests;
DROP TRIGGER cache_policy_revisions_no_truncate ON cache_policy_revisions;
DROP TRIGGER cache_policy_heads_no_truncate ON cache_policy_heads;
DROP FUNCTION prevent_cache_control_truncate();

DROP TRIGGER cache_operation_node_targets_no_delete ON cache_operation_node_targets;
DROP TRIGGER cache_operation_nodes_no_delete ON cache_operation_nodes;
DROP FUNCTION prevent_cache_projection_delete();
DROP TRIGGER cache_operation_commands_protected ON cache_operation_commands;
DROP FUNCTION protect_cache_operation_command();
DROP TRIGGER cache_policy_write_requests_protected ON cache_policy_write_requests;
DROP FUNCTION protect_cache_policy_write_request();
DROP TRIGGER cache_operations_protected ON cache_operations;
DROP FUNCTION protect_cache_operation_transition();
DROP TRIGGER cache_operation_node_targets_protected ON cache_operation_node_targets;
DROP FUNCTION protect_cache_operation_target_transition();
DROP TRIGGER cache_operation_nodes_protected ON cache_operation_nodes;
DROP FUNCTION protect_cache_operation_node_transition();
DROP TRIGGER cache_operation_node_attempts_protected ON cache_operation_node_attempts;
DROP FUNCTION protect_cache_operation_attempt();
DROP TRIGGER cache_operation_target_results_append_only ON cache_operation_target_results;
DROP TRIGGER cache_operation_targets_append_only ON cache_operation_targets;
DROP TRIGGER cache_policy_revisions_append_only ON cache_policy_revisions;
DROP TRIGGER cache_policy_heads_protected ON cache_policy_heads;
DROP FUNCTION protect_cache_policy_head();
DROP FUNCTION prevent_cache_append_only_mutation();

DROP TRIGGER cache_policy_audit_validate_insert ON audit_events;
DROP FUNCTION protect_cache_policy_audit_insert();
DROP TRIGGER cache_operation_audit_validate_insert ON audit_events;
DROP FUNCTION protect_cache_operation_audit_insert();
DROP TRIGGER cache_operation_target_results_validate_insert ON cache_operation_target_results;
DROP FUNCTION validate_cache_operation_target_result_insert();

DROP TABLE cache_operation_target_results;
DROP TABLE cache_operation_node_attempts;
DROP TABLE cache_operation_node_targets;
DROP TABLE cache_operation_nodes;
DROP TABLE cache_operation_targets;
DROP TABLE cache_operation_commands;
DROP TABLE cache_operations;
DROP TABLE cache_policy_write_requests;
DROP TABLE cache_policy_revisions;
DROP TABLE cache_policy_heads;
