LOCK TABLE schema_migrations, users, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_409_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 408 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 408 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=408 AND
        migration_id='408_security_ban_list' AND
        checksum_sha256='2930704b02b72ecf91078d776b2f59fb92cf538dec68e94f7284d3dbfaf52690' AND
        down_checksum_sha256='02e04ab4134098bbd3f7de2faadba530b95d034f0508f783398f356e5c497e49' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='users' AND column_name='password_change_required'
       ) THEN
        RAISE EXCEPTION 'migration 409 requires the exact verified 408 release head' USING ERRCODE='P4090';
    END IF;
END;
$migration_409_up$;

-- 409 (r136 tenant-members2, placeholder number: integration head 403 + 1,
-- renumbered on merge). Tenant member second phase:
--   1. users.password_change_required: an administrator asks a member to
--      change the password at the next sign-in. Every session request except
--      reading the session and changing the password is refused until the
--      member changes it; a successful change clears the flag.
--   2. Handing a removed member's certificates to another member of the same
--      tenant scope. The owner stays immutable (276) except inside a
--      transaction that set cdnca.tenant_member_handover to exactly
--      '<old owner>:<new owner>' (identity.DeleteTenantMember, which checks
--      in the same transaction that the new owner is an active member of the
--      scope; the 085 actor trigger and the owner foreign key still apply).
--   3. The 085 actor check no longer re-checks a certificate's creator on
--      update, so a handed-over certificate stays renewable and deletable
--      after its creator was removed.
ALTER TABLE users ADD COLUMN password_change_required boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        IF OLD.owner_user_id IS NOT NULL AND NEW.owner_user_id IS NOT NULL AND
           current_setting('cdnca.tenant_member_handover', true) =
               OLD.owner_user_id::text || ':' || NEW.owner_user_id::text THEN
            RETURN NEW;
        END IF;
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
        -- The creator is checked when the asset is created; protect_certificate_asset
        -- keeps it unchanged afterwards. Checking it again on every update
        -- froze the certificates of a removed creator (409).
        IF TG_OP = 'INSERT' THEN
            actor_scopes := ARRAY[NEW.created_by_scope_id, NEW.updated_by_scope_id, NEW.deleted_by_scope_id];
            actor_users := ARRAY[NEW.created_by_user_id, NEW.updated_by_user_id, NEW.deleted_by_user_id];
        ELSE
            actor_scopes := ARRAY[NEW.updated_by_scope_id, NEW.deleted_by_scope_id];
            actor_users := ARRAY[NEW.updated_by_user_id, NEW.deleted_by_user_id];
        END IF;
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

