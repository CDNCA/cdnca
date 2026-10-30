LOCK TABLE schema_migrations, users, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_409_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 409 OR
       (SELECT max(version) FROM schema_migrations) <> 409 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=409 AND
        migration_id='409_tenant_member_handover' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 409 down requires the exact verified migration head' USING ERRCODE='P4091';
    END IF;
    -- A pending "change the password at next sign-in" is an administrator's
    -- decision; dropping it would let the member keep the old password.
    IF EXISTS (SELECT 1 FROM users WHERE password_change_required) THEN
        RAISE EXCEPTION 'migration 409 rollback would discard pending password change requirements' USING ERRCODE='P4092';
    END IF;
END;
$migration_409_down$;

CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        RAISE EXCEPTION 'certificate asset owner is immutable' USING ERRCODE='P2761';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app;

CREATE OR REPLACE FUNCTION validate_certificate_asset_actor_target_085()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_scopes uuid[];
    actor_users uuid[];
    actor_kind text;
    actor_membership text;
    actor_status text;
    pair_index integer;
BEGIN
    IF TG_TABLE_NAME = 'certificate_assets' THEN
        actor_scopes := ARRAY[NEW.created_by_scope_id, NEW.updated_by_scope_id, NEW.deleted_by_scope_id];
        actor_users := ARRAY[NEW.created_by_user_id, NEW.updated_by_user_id, NEW.deleted_by_user_id];
    ELSE
        actor_scopes := ARRAY[(to_jsonb(NEW)->>'actor_scope_id')::uuid];
        actor_users := ARRAY[COALESCE(
            to_jsonb(NEW)->>'actor_user_id',
            to_jsonb(NEW)->>'imported_by_user_id',
            to_jsonb(NEW)->>'changed_by_user_id',
            to_jsonb(NEW)->>'activated_by_user_id',
            to_jsonb(NEW)->>'revoked_by_user_id'
        )::uuid];
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant' AND tenant.status = 'active'
    ) THEN
        RAISE EXCEPTION 'certificate asset target tenant is invalid' USING ERRCODE = 'P8502';
    END IF;
    FOR pair_index IN 1..array_length(actor_scopes, 1) LOOP
        IF actor_scopes[pair_index] IS NULL AND actor_users[pair_index] IS NULL THEN
            CONTINUE;
        END IF;
        IF actor_scopes[pair_index] IS NULL OR actor_users[pair_index] IS NULL THEN
            RAISE EXCEPTION 'certificate asset actor identity is incomplete' USING ERRCODE = 'P8502';
        END IF;
        SELECT scope.kind, membership.status, account.status
          INTO actor_kind, actor_membership, actor_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users account ON account.id = membership.user_id
        WHERE scope.id = actor_scopes[pair_index] AND membership.user_id = actor_users[pair_index];
        IF actor_kind NOT IN ('tenant', 'platform') OR actor_membership IS DISTINCT FROM 'active'
           OR actor_status IS DISTINCT FROM 'active'
           OR (actor_kind = 'tenant' AND actor_scopes[pair_index] <> NEW.tenant_scope_id) THEN
            RAISE EXCEPTION 'certificate asset actor target boundary is invalid' USING ERRCODE = 'P8502';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

ALTER TABLE users DROP COLUMN password_change_required;
