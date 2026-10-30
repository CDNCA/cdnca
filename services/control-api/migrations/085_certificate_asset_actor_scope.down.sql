LOCK TABLE schema_migrations,
    access_scopes,
    users,
    memberships,
    roles,
    role_permissions,
    certificate_assets,
    certificate_asset_versions,
    certificate_asset_private_key_envelope_facts,
    certificate_asset_activation_facts,
    certificate_asset_revocation_facts,
    certificate_site_binding_facts,
    certificate_asset_write_requests,
    certificate_asset_rbac_grant_additions_085
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 85 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 85 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 85 AND migration_id = '085_certificate_asset_actor_scope'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 085 rollback requires the verified 085 head'
            USING ERRCODE = 'P8501';
    END IF;

    IF EXISTS (
        SELECT 1 FROM certificate_assets
        WHERE created_by_scope_id <> tenant_scope_id
           OR updated_by_scope_id <> tenant_scope_id
           OR deleted_by_scope_id IS DISTINCT FROM CASE WHEN deleted_by_user_id IS NULL THEN NULL ELSE tenant_scope_id END
    ) OR EXISTS (
        SELECT 1 FROM certificate_asset_versions WHERE actor_scope_id <> tenant_scope_id
    ) OR EXISTS (
        SELECT 1 FROM certificate_asset_private_key_envelope_facts WHERE actor_scope_id <> tenant_scope_id
    ) OR EXISTS (
        SELECT 1 FROM certificate_asset_activation_facts WHERE actor_scope_id <> tenant_scope_id
    ) OR EXISTS (
        SELECT 1 FROM certificate_asset_revocation_facts WHERE actor_scope_id <> tenant_scope_id
    ) OR EXISTS (
        SELECT 1 FROM certificate_site_binding_facts WHERE actor_scope_id <> tenant_scope_id
    ) OR EXISTS (
        SELECT 1 FROM certificate_asset_write_requests WHERE actor_scope_id <> tenant_scope_id
    ) THEN
        RAISE EXCEPTION 'migration 085 rollback would discard platform certificate actor identity facts'
            USING ERRCODE = 'P8501';
    END IF;
END;
$$;

DROP TRIGGER certificate_asset_writes_actor_target_085 ON certificate_asset_write_requests;
DROP TRIGGER certificate_site_bindings_actor_target_085 ON certificate_site_binding_facts;
DROP TRIGGER certificate_asset_revocations_actor_target_085 ON certificate_asset_revocation_facts;
DROP TRIGGER certificate_asset_activations_actor_target_085 ON certificate_asset_activation_facts;
DROP TRIGGER certificate_asset_envelopes_actor_target_085 ON certificate_asset_private_key_envelope_facts;
DROP TRIGGER certificate_asset_versions_actor_target_085 ON certificate_asset_versions;
DROP TRIGGER certificate_assets_actor_target_085 ON certificate_assets;
DROP FUNCTION validate_certificate_asset_actor_target_085();

ALTER TABLE certificate_asset_write_requests
    DROP CONSTRAINT certificate_asset_write_actor_idempotency_085_key,
    DROP CONSTRAINT certificate_asset_write_actor_085_fk;
ALTER TABLE certificate_site_binding_facts DROP CONSTRAINT certificate_site_binding_actor_085_fk;
ALTER TABLE certificate_asset_revocation_facts DROP CONSTRAINT certificate_asset_revocation_actor_085_fk;
ALTER TABLE certificate_asset_activation_facts DROP CONSTRAINT certificate_asset_activation_actor_085_fk;
ALTER TABLE certificate_asset_private_key_envelope_facts DROP CONSTRAINT certificate_asset_envelope_actor_085_fk;
ALTER TABLE certificate_asset_versions DROP CONSTRAINT certificate_asset_versions_actor_085_fk;
ALTER TABLE certificate_assets
    DROP CONSTRAINT certificate_assets_created_actor_085_fk,
    DROP CONSTRAINT certificate_assets_updated_actor_085_fk,
    DROP CONSTRAINT certificate_assets_deleted_actor_085_fk,
    DROP CONSTRAINT certificate_assets_deleted_actor_085_check;

ALTER TABLE certificate_assets
    ADD FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (tenant_scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (tenant_scope_id, deleted_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_versions
    ADD FOREIGN KEY (tenant_scope_id, imported_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_private_key_envelope_facts
    ADD FOREIGN KEY (tenant_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_activation_facts
    ADD FOREIGN KEY (tenant_scope_id, activated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_revocation_facts
    ADD FOREIGN KEY (tenant_scope_id, revoked_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_site_binding_facts
    ADD FOREIGN KEY (tenant_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_write_requests
    ADD FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key);

ALTER TABLE certificate_asset_write_requests DROP COLUMN actor_scope_id;
ALTER TABLE certificate_site_binding_facts DROP COLUMN actor_scope_id;
ALTER TABLE certificate_asset_revocation_facts DROP COLUMN actor_scope_id;
ALTER TABLE certificate_asset_activation_facts DROP COLUMN actor_scope_id;
ALTER TABLE certificate_asset_private_key_envelope_facts DROP COLUMN actor_scope_id;
ALTER TABLE certificate_asset_versions DROP COLUMN actor_scope_id;
ALTER TABLE certificate_assets
    DROP COLUMN deleted_by_scope_id,
    DROP COLUMN updated_by_scope_id,
    DROP COLUMN created_by_scope_id;

CREATE OR REPLACE FUNCTION protect_certificate_asset()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'certificate assets cannot be physically removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'certificate asset must start at revision one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted certificate asset is immutable';
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.source IS DISTINCT FROM OLD.source
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'certificate asset revision must advance by one';
    END IF;
    IF NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (site_id) site_id, action, asset_id
            FROM certificate_site_binding_facts
            WHERE tenant_scope_id = OLD.tenant_scope_id
            ORDER BY site_id, sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'referenced certificate asset cannot be deleted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_certificate_asset_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'certificate asset write requests cannot be truncated';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.resource_id IS NOT NULL OR NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'certificate asset write request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'certificate asset write requests cannot be deleted';
    END IF;
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed certificate asset write request is immutable';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.resource_id IS NULL OR NEW.response_body IS NULL OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'certificate asset write request must complete atomically';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE certificate_asset_rbac_grant_additions_085
    DROP CONSTRAINT certificate_asset_rbac_grant_role_permission_085_fk;
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions permission
USING certificate_asset_rbac_grant_additions_085 addition
WHERE permission.role_id = addition.role_id
  AND permission.permission_name = addition.permission_name
  AND addition.source_migration = 85;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DROP TABLE certificate_asset_rbac_grant_additions_085;
