LOCK TABLE schema_migrations,access_scopes,users,memberships,roles,role_assignments,
    role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_165$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>164 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>164 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=164 AND migration_id='164_package_period_reset' AND
              checksum_sha256='79f38f20d69e4d2e922b77263bfb5b86a242c117f8c19afd38bf37104401dd60' AND
              down_checksum_sha256='0a711b4313ef1e750e333e564a94359dfc57ffd853697ec5e33dd05670bbe758' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('package_period_reset_workload_authority_bindings_165') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 165 requires the exact verified 164 release head'
            USING ERRCODE='P1650';
    END IF;
END;
$migration_165$;

CREATE TABLE package_period_reset_workload_authority_bindings_165 (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    audience text NOT NULL CHECK(audience='package_period_reset'),
    permission_name text NOT NULL CHECK(permission_name='sites.manage'),
    status text NOT NULL CHECK(status IN ('active','revoked')),
    revision bigint NOT NULL CHECK(revision>0),
    not_before timestamptz NOT NULL CHECK(isfinite(not_before)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>not_before),
    revoked_at timestamptz CHECK(revoked_at IS NULL OR isfinite(revoked_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(tenant_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK(
        (status='active' AND revoked_at IS NULL) OR
        (status='revoked' AND revoked_at IS NOT NULL AND revoked_at>=created_at)
    )
);

CREATE UNIQUE INDEX package_period_reset_workload_authority_active_tenant_165
    ON package_period_reset_workload_authority_bindings_165(tenant_scope_id)
    WHERE revoked_at IS NULL;

CREATE FUNCTION protect_package_period_reset_workload_authority_binding_165()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scope_kind text;
    account_status text;
    membership_status text;
    permission_allowed boolean;
BEGIN
    IF TG_OP='TRUNCATE' THEN
        RAISE EXCEPTION 'package period reset workload authority bindings cannot be truncated' USING ERRCODE='P1651';
    ELSIF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'package period reset workload authority bindings cannot be deleted' USING ERRCODE='P1651';
    ELSIF TG_OP='INSERT' THEN
        IF NEW.status<>'active' OR NEW.revision<>1 OR NEW.revoked_at IS NOT NULL OR NEW.updated_at<>NEW.created_at THEN
            RAISE EXCEPTION 'package period reset workload authority binding must start active at revision 1'
                USING ERRCODE='P1651';
        END IF;
        SELECT scope.kind,account.status,membership.status,EXISTS(
            SELECT 1 FROM custom_rbac_effective_permissions(NEW.tenant_scope_id,NEW.actor_user_id)
            WHERE permission_name='sites.manage'
        ) INTO scope_kind,account_status,membership_status,permission_allowed
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=NEW.actor_user_id
        JOIN users account ON account.id=membership.user_id
        WHERE scope.id=NEW.tenant_scope_id;
        IF scope_kind IS DISTINCT FROM 'tenant' OR account_status IS DISTINCT FROM 'active' OR
           membership_status IS DISTINCT FROM 'active' OR permission_allowed IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'package period reset workload authority binding requires an active tenant actor with sites.manage'
                USING ERRCODE='P1651';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status<>'active' OR NEW.status<>'revoked' OR NEW.revision<>OLD.revision+1 OR
       NEW.revoked_at IS NULL OR NEW.updated_at<>NEW.revoked_at OR NEW.revoked_at<OLD.created_at OR
       NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR NEW.audience IS DISTINCT FROM OLD.audience OR
       NEW.permission_name IS DISTINCT FROM OLD.permission_name OR NEW.not_before IS DISTINCT FROM OLD.not_before OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package period reset workload authority binding only permits one-way revocation'
            USING ERRCODE='P1651';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_period_reset_workload_authority_binding_guard_165
BEFORE INSERT OR UPDATE OR DELETE ON package_period_reset_workload_authority_bindings_165
FOR EACH ROW EXECUTE FUNCTION protect_package_period_reset_workload_authority_binding_165();
CREATE TRIGGER package_period_reset_workload_authority_binding_no_truncate_165
BEFORE TRUNCATE ON package_period_reset_workload_authority_bindings_165
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_period_reset_workload_authority_binding_165();

REVOKE ALL ON package_period_reset_workload_authority_bindings_165 FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_period_reset_workload_authority_binding_165() FROM PUBLIC;
