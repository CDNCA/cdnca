LOCK TABLE cache_policy_heads,
    cache_policy_revisions,
    cache_policy_write_requests,
    cache_operations,
    cache_operation_commands,
    memberships,
    audit_events,
    edge_configuration_scopes
IN ACCESS EXCLUSIVE MODE;

ALTER TABLE cache_operations ADD COLUMN actor_scope_id uuid;
ALTER TABLE cache_policy_write_requests ADD COLUMN actor_scope_id uuid;
ALTER TABLE cache_operation_commands ADD COLUMN actor_scope_id uuid;
ALTER TABLE cache_policy_revisions
    ADD COLUMN actor_scope_id uuid,
    ADD COLUMN edge_source_revision bigint;

ALTER TABLE cache_operations DISABLE TRIGGER cache_operations_protected;
ALTER TABLE cache_policy_write_requests DISABLE TRIGGER cache_policy_write_requests_protected;
ALTER TABLE cache_operation_commands DISABLE TRIGGER cache_operation_commands_protected;
ALTER TABLE cache_policy_revisions DISABLE TRIGGER cache_policy_revisions_append_only;

UPDATE cache_operations SET actor_scope_id = scope_id;
UPDATE cache_policy_write_requests SET actor_scope_id = scope_id;
UPDATE cache_operation_commands SET actor_scope_id = scope_id;
UPDATE cache_policy_revisions SET actor_scope_id = scope_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM cache_policy_revisions revision
        LEFT JOIN edge_configuration_scopes edge_scope ON edge_scope.scope_id = revision.scope_id
        WHERE edge_scope.scope_id IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8000',
            MESSAGE = 'cache policy revision has no edge configuration scope';
    END IF;
END;
$$;

WITH ranked AS (
    SELECT revision.ctid,
           edge_scope.source_revision + row_number() OVER (
               PARTITION BY revision.scope_id
               ORDER BY revision.created_at, revision.site_id, revision.revision
           ) AS edge_source_revision
    FROM cache_policy_revisions revision
    JOIN edge_configuration_scopes edge_scope ON edge_scope.scope_id = revision.scope_id
)
UPDATE cache_policy_revisions revision
SET edge_source_revision = ranked.edge_source_revision
FROM ranked
WHERE revision.ctid = ranked.ctid;

WITH maxima AS (
    SELECT scope_id, max(edge_source_revision) AS edge_source_revision
    FROM cache_policy_revisions
    GROUP BY scope_id
)
UPDATE edge_configuration_scopes edge_scope
SET source_revision = maxima.edge_source_revision,
    updated_at = CURRENT_TIMESTAMP
FROM maxima
WHERE edge_scope.scope_id = maxima.scope_id
  AND edge_scope.source_revision < maxima.edge_source_revision;

SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE cache_policy_revisions ENABLE TRIGGER cache_policy_revisions_append_only;
ALTER TABLE cache_operation_commands ENABLE TRIGGER cache_operation_commands_protected;
ALTER TABLE cache_policy_write_requests ENABLE TRIGGER cache_policy_write_requests_protected;
ALTER TABLE cache_operations ENABLE TRIGGER cache_operations_protected;
SET CONSTRAINTS ALL DEFERRED;

ALTER TABLE cache_operations
    ALTER COLUMN actor_scope_id SET NOT NULL,
    DROP CONSTRAINT cache_operations_scope_id_actor_user_id_fkey,
    DROP CONSTRAINT cache_operations_scope_id_idempotency_key_key,
    ADD CONSTRAINT cache_operations_actor_membership_080_fkey
        FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_operations_idempotency_080_key
        UNIQUE (scope_id, actor_scope_id, actor_user_id, idempotency_key);

ALTER TABLE cache_policy_write_requests
    ALTER COLUMN actor_scope_id SET NOT NULL,
    DROP CONSTRAINT cache_policy_write_requests_scope_id_actor_user_id_fkey,
    DROP CONSTRAINT cache_policy_write_requests_scope_id_idempotency_key_key,
    ADD CONSTRAINT cache_policy_write_requests_actor_membership_080_fkey
        FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_policy_write_requests_idempotency_080_key
        UNIQUE (scope_id, actor_scope_id, actor_user_id, idempotency_key);

ALTER TABLE cache_operation_commands
    ALTER COLUMN actor_scope_id SET NOT NULL,
    DROP CONSTRAINT cache_operation_commands_scope_id_actor_user_id_fkey,
    DROP CONSTRAINT cache_operation_commands_scope_id_operation_id_command_idem_key,
    ADD CONSTRAINT cache_operation_commands_actor_membership_080_fkey
        FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_operation_commands_idempotency_080_key
        UNIQUE (
            scope_id, actor_scope_id, actor_user_id,
            operation_id, command, idempotency_key
        );

ALTER TABLE cache_policy_revisions
    ALTER COLUMN actor_scope_id SET NOT NULL,
    ALTER COLUMN edge_source_revision SET NOT NULL,
    DROP CONSTRAINT cache_policy_revisions_scope_id_created_by_user_id_fkey,
    ADD CONSTRAINT cache_policy_revisions_actor_membership_080_fkey
        FOREIGN KEY (actor_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_policy_revisions_edge_source_revision_080_check
        CHECK (edge_source_revision > 0),
    ADD CONSTRAINT cache_policy_revisions_edge_source_revision_080_key
        UNIQUE (scope_id, edge_source_revision);

CREATE FUNCTION protect_cache_actor_scope_080()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8001',
            MESSAGE = 'cache actor scope is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operations_actor_scope_immutable_080
BEFORE UPDATE ON cache_operations
FOR EACH ROW EXECUTE FUNCTION protect_cache_actor_scope_080();
CREATE TRIGGER cache_policy_write_requests_actor_scope_immutable_080
BEFORE UPDATE ON cache_policy_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_cache_actor_scope_080();
CREATE TRIGGER cache_operation_commands_actor_scope_immutable_080
BEFORE UPDATE ON cache_operation_commands
FOR EACH ROW EXECUTE FUNCTION protect_cache_actor_scope_080();
CREATE TRIGGER cache_policy_revisions_actor_scope_immutable_080
BEFORE UPDATE ON cache_policy_revisions
FOR EACH ROW EXECUTE FUNCTION protect_cache_actor_scope_080();

CREATE FUNCTION validate_cache_policy_actor_scope_080()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_site_id uuid;
    checked_scope_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action <> 'cache_policy.publish' THEN
            RETURN NULL;
        END IF;
        BEGIN
            checked_site_id := NEW.resource_id::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P8002',
                MESSAGE = 'cache policy actor integrity has invalid audit resource';
        END;
        checked_scope_id := NEW.scope_id;
    ELSE
        checked_site_id := COALESCE(NEW.site_id, OLD.site_id);
        checked_scope_id := COALESCE(NEW.scope_id, OLD.scope_id);
    END IF;

    IF EXISTS (
        SELECT 1
        FROM cache_policy_revisions revision
        WHERE revision.scope_id = checked_scope_id
          AND revision.site_id = checked_site_id
          AND (
              1 <> (
                  SELECT count(*)
                  FROM cache_policy_write_requests request
                  WHERE request.scope_id = revision.scope_id
                    AND request.site_id = revision.site_id
                    AND request.actor_scope_id = revision.actor_scope_id
                    AND request.actor_user_id = revision.created_by_user_id
                    AND request.request_digest = revision.request_digest
                    AND request.response_revision = revision.revision
                    AND request.completed_at IS NOT NULL
              ) OR
              1 <> (
                  SELECT count(*)
                  FROM audit_events event
                  WHERE event.scope_id = revision.scope_id
                    AND event.actor_user_id = revision.created_by_user_id
                    AND event.action = 'cache_policy.publish'
                    AND event.resource_type = 'cache_policy'
                    AND event.resource_id = revision.site_id::text
                    AND event.request_id = revision.request_id
                    AND event.result = 'success'
                    AND event.payload->>'revision' = revision.revision::text
                    AND (
                        (event.payload ? 'actor_scope_id' AND
                         event.payload->>'actor_scope_id' = revision.actor_scope_id::text) OR
                        (NOT (event.payload ? 'actor_scope_id') AND
                         event.scope_id = revision.actor_scope_id)
                    )
              )
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8002',
            MESSAGE = 'cache policy actor scope integrity violation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cache_policy_revisions_actor_integrity_080
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_actor_scope_080();
CREATE CONSTRAINT TRIGGER cache_policy_write_requests_actor_integrity_080
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_actor_scope_080();
CREATE CONSTRAINT TRIGGER cache_policy_audit_actor_integrity_080
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.action = 'cache_policy.publish')
EXECUTE FUNCTION validate_cache_policy_actor_scope_080();

CREATE FUNCTION validate_cache_operation_actor_scope_080()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_operation_id uuid;
    operation_row cache_operations%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action NOT LIKE 'cache.operation.%' THEN
            RETURN NULL;
        END IF;
        BEGIN
            checked_operation_id := NEW.resource_id::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P8004',
                MESSAGE = 'cache operation actor integrity has invalid audit resource';
        END;
    ELSIF TG_TABLE_NAME = 'cache_operations' THEN
        checked_operation_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_operation_id := COALESCE(NEW.operation_id, OLD.operation_id);
    END IF;

    SELECT * INTO operation_row
    FROM cache_operations
    WHERE id = checked_operation_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF 1 <> (
        SELECT count(*)
        FROM audit_events event
        WHERE event.scope_id = operation_row.scope_id
          AND event.actor_user_id = operation_row.actor_user_id
          AND event.action = 'cache.operation.create'
          AND event.resource_type = 'cache_operation'
          AND event.resource_id = operation_row.id::text
          AND event.result = 'success'
          AND (
              (event.payload ? 'actor_scope_id' AND
               event.payload->>'actor_scope_id' = operation_row.actor_scope_id::text) OR
              (NOT (event.payload ? 'actor_scope_id') AND
               event.scope_id = operation_row.actor_scope_id)
          )
    ) OR EXISTS (
        SELECT 1
        FROM cache_operation_commands command
        WHERE command.operation_id = operation_row.id
          AND 1 <> (
              SELECT count(*)
              FROM audit_events event
              WHERE event.scope_id = command.scope_id
                AND event.actor_user_id = command.actor_user_id
                AND event.action = 'cache.operation.' || command.command
                AND event.resource_type = 'cache_operation'
                AND event.resource_id = command.operation_id::text
                AND event.result = 'success'
                AND event.payload->>'command_id' = command.id::text
                AND (
                    (event.payload ? 'actor_scope_id' AND
                     event.payload->>'actor_scope_id' = command.actor_scope_id::text) OR
                    (NOT (event.payload ? 'actor_scope_id') AND
                     event.scope_id = command.actor_scope_id)
                )
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8004',
            MESSAGE = 'cache operation actor scope integrity violation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cache_operations_actor_integrity_080
AFTER INSERT OR UPDATE OR DELETE ON cache_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_actor_scope_080();
CREATE CONSTRAINT TRIGGER cache_operation_commands_actor_integrity_080
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_actor_scope_080();
CREATE CONSTRAINT TRIGGER cache_operation_audit_actor_integrity_080
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.action LIKE 'cache.operation.%')
EXECUTE FUNCTION validate_cache_operation_actor_scope_080();

CREATE FUNCTION validate_cache_policy_edge_source_revision_080()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_source_revision bigint;
BEGIN
    SELECT source_revision INTO current_source_revision
    FROM edge_configuration_scopes
    WHERE scope_id = NEW.scope_id
    FOR SHARE;
    IF NOT FOUND OR NEW.edge_source_revision IS DISTINCT FROM current_source_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8005',
            MESSAGE = 'cache policy edge source revision must match the current edge scope head';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_revisions_edge_binding_080
BEFORE INSERT ON cache_policy_revisions
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_edge_source_revision_080();
