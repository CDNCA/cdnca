LOCK TABLE schema_migrations, acme_tenant_key_facts, acme_account_registration_facts,
    acme_issuance_operations, certificate_orders, acme_renewal_claim_facts
IN ACCESS EXCLUSIVE MODE;

DO $migration_531_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 531 OR
       (SELECT max(version) FROM schema_migrations) <> 531 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=531 AND
        migration_id='531_acme_platform_actor' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 531 down requires the exact verified migration head' USING ERRCODE='P5311';
    END IF;
    -- 048's foreign keys require the actor to be a member of the target
    -- tenant: facts written by platform members cannot be kept, so refuse
    -- instead of rewriting who acted.
    IF EXISTS (SELECT 1 FROM acme_tenant_key_facts fact WHERE NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.tenant_scope_id AND m.user_id = fact.created_by_user_id))
       OR EXISTS (SELECT 1 FROM acme_account_registration_facts fact WHERE NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.tenant_scope_id AND m.user_id = fact.created_by_user_id))
       OR EXISTS (SELECT 1 FROM acme_issuance_operations fact WHERE NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.tenant_scope_id AND m.user_id = fact.actor_user_id))
       OR EXISTS (SELECT 1 FROM certificate_orders fact WHERE NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.scope_id AND m.user_id = fact.created_by_user_id)
            OR NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.scope_id AND m.user_id = fact.updated_by_user_id))
       OR EXISTS (SELECT 1 FROM acme_renewal_claim_facts fact WHERE NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id = fact.tenant_scope_id AND m.user_id = fact.actor_user_id)) THEN
        RAISE EXCEPTION 'migration 531 rollback would orphan ACME facts written by platform members' USING ERRCODE='P5312';
    END IF;
END;
$migration_531_down$;

ALTER TABLE acme_tenant_key_facts
    DROP CONSTRAINT acme_tenant_key_facts_actor_fk_531,
    ADD CONSTRAINT acme_tenant_key_facts_actor_fk_048
        FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE acme_account_registration_facts
    DROP CONSTRAINT acme_account_registration_actor_fk_531,
    ADD CONSTRAINT acme_account_registration_actor_fk_048
        FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE acme_issuance_operations
    DROP CONSTRAINT acme_issuance_operations_actor_fk_531,
    ADD CONSTRAINT acme_issuance_operations_actor_fk_048
        FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_orders
    DROP CONSTRAINT certificate_orders_created_actor_fk_531,
    DROP CONSTRAINT certificate_orders_updated_actor_fk_531,
    ADD CONSTRAINT certificate_orders_created_actor_fk_048
        FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_orders_updated_actor_fk_048
        FOREIGN KEY (scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE acme_renewal_claim_facts
    DROP CONSTRAINT acme_renewal_claim_actor_fk_531,
    ADD CONSTRAINT acme_renewal_claim_actor_fk_048
        FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

-- 047's snapshot check back to its own tenant-membership lookup.
CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_tenant_id uuid;
    snapshot_scope_id uuid;
    snapshot_actor_id uuid;
    scope_tenant_id uuid;
BEGIN
    BEGIN
        snapshot_tenant_id := (NEW.request_snapshot ->> 'TenantID')::uuid;
        snapshot_scope_id := (NEW.request_snapshot ->> 'ScopeID')::uuid;
        snapshot_actor_id := (NEW.request_snapshot ->> 'ActorUserID')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'ACME issuance request snapshot identity is invalid' USING ERRCODE = 'P0001';
    END;

    SELECT scope.tenant_id INTO scope_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant';
    IF NOT FOUND
       OR snapshot_tenant_id IS NULL
       OR snapshot_scope_id IS NULL
       OR snapshot_actor_id IS NULL
       OR snapshot_scope_id IS DISTINCT FROM NEW.tenant_scope_id
       OR snapshot_tenant_id IS DISTINCT FROM scope_tenant_id
       OR NOT EXISTS (
           SELECT 1
           FROM tenants tenant
           JOIN memberships membership
             ON membership.scope_id = NEW.tenant_scope_id
            AND membership.user_id = snapshot_actor_id
            AND membership.status = 'active'
           JOIN users account
             ON account.id = snapshot_actor_id
            AND account.status = 'active'
           WHERE tenant.id = scope_tenant_id AND tenant.status = 'active'
       ) THEN
        RAISE EXCEPTION 'ACME issuance request snapshot is not bound to an active tenant actor'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

-- Back to tenant members only. The body keeps $1/$2: restoring 048's
-- column-shadowed comparison would reopen the cross-tenant pass.
CREATE OR REPLACE FUNCTION acme_runtime_actor_is_active_048(scope_id uuid, actor_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id
         AND membership.user_id = $2
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        WHERE scope.id = $1 AND scope.kind = 'tenant'
    )
$$;
