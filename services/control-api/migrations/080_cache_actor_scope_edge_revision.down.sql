LOCK TABLE cache_policy_heads,
    cache_policy_revisions,
    cache_policy_write_requests,
    cache_operations,
    cache_operation_commands,
    memberships,
    audit_events,
    edge_configuration_scopes
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM cache_operations WHERE actor_scope_id <> scope_id
    ) OR EXISTS (
        SELECT 1 FROM cache_policy_write_requests WHERE actor_scope_id <> scope_id
    ) OR EXISTS (
        SELECT 1 FROM cache_operation_commands WHERE actor_scope_id <> scope_id
    ) OR EXISTS (
        SELECT 1 FROM cache_policy_revisions WHERE actor_scope_id <> scope_id
    ) OR EXISTS (
        SELECT 1 FROM cache_operations
        GROUP BY scope_id, idempotency_key HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1 FROM cache_policy_write_requests
        GROUP BY scope_id, idempotency_key HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1 FROM cache_operation_commands
        GROUP BY scope_id, operation_id, command, idempotency_key HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8009',
            MESSAGE = 'migration 080 rollback cannot represent actor-scoped cache facts';
    END IF;
END;
$$;

DROP TRIGGER cache_policy_revisions_edge_binding_080 ON cache_policy_revisions;
DROP FUNCTION validate_cache_policy_edge_source_revision_080();

DROP TRIGGER cache_operation_audit_actor_integrity_080 ON audit_events;
DROP TRIGGER cache_operation_commands_actor_integrity_080 ON cache_operation_commands;
DROP TRIGGER cache_operations_actor_integrity_080 ON cache_operations;
DROP FUNCTION validate_cache_operation_actor_scope_080();

DROP TRIGGER cache_policy_audit_actor_integrity_080 ON audit_events;
DROP TRIGGER cache_policy_write_requests_actor_integrity_080 ON cache_policy_write_requests;
DROP TRIGGER cache_policy_revisions_actor_integrity_080 ON cache_policy_revisions;
DROP FUNCTION validate_cache_policy_actor_scope_080();

DROP TRIGGER cache_policy_revisions_actor_scope_immutable_080 ON cache_policy_revisions;
DROP TRIGGER cache_operation_commands_actor_scope_immutable_080 ON cache_operation_commands;
DROP TRIGGER cache_policy_write_requests_actor_scope_immutable_080 ON cache_policy_write_requests;
DROP TRIGGER cache_operations_actor_scope_immutable_080 ON cache_operations;
DROP FUNCTION protect_cache_actor_scope_080();

ALTER TABLE cache_policy_revisions
    DROP CONSTRAINT cache_policy_revisions_edge_source_revision_080_key,
    DROP CONSTRAINT cache_policy_revisions_edge_source_revision_080_check,
    DROP CONSTRAINT cache_policy_revisions_actor_membership_080_fkey,
    ADD CONSTRAINT cache_policy_revisions_scope_id_created_by_user_id_fkey
        FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    DROP COLUMN edge_source_revision,
    DROP COLUMN actor_scope_id;

ALTER TABLE cache_operation_commands
    DROP CONSTRAINT cache_operation_commands_idempotency_080_key,
    DROP CONSTRAINT cache_operation_commands_actor_membership_080_fkey,
    ADD CONSTRAINT cache_operation_commands_scope_id_actor_user_id_fkey
        FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_operation_commands_scope_id_operation_id_command_idem_key
        UNIQUE (scope_id, operation_id, command, idempotency_key),
    DROP COLUMN actor_scope_id;

ALTER TABLE cache_policy_write_requests
    DROP CONSTRAINT cache_policy_write_requests_idempotency_080_key,
    DROP CONSTRAINT cache_policy_write_requests_actor_membership_080_fkey,
    ADD CONSTRAINT cache_policy_write_requests_scope_id_actor_user_id_fkey
        FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_policy_write_requests_scope_id_idempotency_key_key
        UNIQUE (scope_id, idempotency_key),
    DROP COLUMN actor_scope_id;

ALTER TABLE cache_operations
    DROP CONSTRAINT cache_operations_idempotency_080_key,
    DROP CONSTRAINT cache_operations_actor_membership_080_fkey,
    ADD CONSTRAINT cache_operations_scope_id_actor_user_id_fkey
        FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_operations_scope_id_idempotency_key_key
        UNIQUE (scope_id, idempotency_key),
    DROP COLUMN actor_scope_id;
