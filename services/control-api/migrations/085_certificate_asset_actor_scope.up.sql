LOCK TABLE schema_migrations,
    access_scopes,
    tenants,
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
    certificate_asset_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 84 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 84 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 84 AND migration_id = '084_plugin_webhook_control'
          AND checksum_sha256 = 'f51e909422b4254b49204d85cd4adec7ad0fed9da29686fd872651010220a56d'
          AND down_checksum_sha256 = 'b914352bc35e24c6bd9d12b90255ab42586dfb9e31438825961c02cb37cbc3be'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'certificate asset actor scope requires frozen verified migration head 084'
            USING ERRCODE = 'P8500';
    END IF;
END;
$$;

CREATE TABLE certificate_asset_rbac_grant_additions_085 (
    role_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    permission_name text NOT NULL,
    source_migration smallint NOT NULL DEFAULT 85 CHECK (source_migration = 85),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (scope_id, role_id) REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT certificate_asset_rbac_grant_role_permission_085_fk
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT
);

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, permission.name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    CROSS JOIN (VALUES ('certificates.read'), ('certificates.manage')) permission(name)
    WHERE role.system_role AND scope.kind = 'platform'
      AND role.name IN ('platform_owner', 'platform_admin')
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO certificate_asset_rbac_grant_additions_085(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id = addition.role_id;

ALTER TABLE certificate_assets
    ADD COLUMN created_by_scope_id uuid,
    ADD COLUMN updated_by_scope_id uuid,
    ADD COLUMN deleted_by_scope_id uuid;
ALTER TABLE certificate_asset_versions ADD COLUMN actor_scope_id uuid;
ALTER TABLE certificate_asset_private_key_envelope_facts ADD COLUMN actor_scope_id uuid;
ALTER TABLE certificate_asset_activation_facts ADD COLUMN actor_scope_id uuid;
ALTER TABLE certificate_asset_revocation_facts ADD COLUMN actor_scope_id uuid;
ALTER TABLE certificate_site_binding_facts ADD COLUMN actor_scope_id uuid;
ALTER TABLE certificate_asset_write_requests ADD COLUMN actor_scope_id uuid;

ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_protect;
ALTER TABLE certificate_asset_versions DISABLE TRIGGER certificate_asset_versions_immutable;
ALTER TABLE certificate_asset_private_key_envelope_facts
    DISABLE TRIGGER certificate_asset_private_key_envelopes_immutable;
ALTER TABLE certificate_asset_activation_facts DISABLE TRIGGER certificate_asset_activations_immutable;
ALTER TABLE certificate_asset_revocation_facts DISABLE TRIGGER certificate_asset_revocations_immutable;
ALTER TABLE certificate_site_binding_facts DISABLE TRIGGER certificate_site_bindings_immutable;
ALTER TABLE certificate_asset_write_requests DISABLE TRIGGER certificate_asset_write_requests_protect;

UPDATE certificate_assets
SET created_by_scope_id = tenant_scope_id,
    updated_by_scope_id = tenant_scope_id,
    deleted_by_scope_id = CASE WHEN deleted_by_user_id IS NULL THEN NULL ELSE tenant_scope_id END;
UPDATE certificate_asset_versions SET actor_scope_id = tenant_scope_id;
UPDATE certificate_asset_private_key_envelope_facts SET actor_scope_id = tenant_scope_id;
UPDATE certificate_asset_activation_facts SET actor_scope_id = tenant_scope_id;
UPDATE certificate_asset_revocation_facts SET actor_scope_id = tenant_scope_id;
UPDATE certificate_site_binding_facts SET actor_scope_id = tenant_scope_id;
UPDATE certificate_asset_write_requests SET actor_scope_id = tenant_scope_id;

ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_protect;
ALTER TABLE certificate_asset_versions ENABLE TRIGGER certificate_asset_versions_immutable;
ALTER TABLE certificate_asset_private_key_envelope_facts
    ENABLE TRIGGER certificate_asset_private_key_envelopes_immutable;
ALTER TABLE certificate_asset_activation_facts ENABLE TRIGGER certificate_asset_activations_immutable;
ALTER TABLE certificate_asset_revocation_facts ENABLE TRIGGER certificate_asset_revocations_immutable;
ALTER TABLE certificate_site_binding_facts ENABLE TRIGGER certificate_site_bindings_immutable;
ALTER TABLE certificate_asset_write_requests ENABLE TRIGGER certificate_asset_write_requests_protect;

ALTER TABLE certificate_assets
    ALTER COLUMN created_by_scope_id SET NOT NULL,
    ALTER COLUMN updated_by_scope_id SET NOT NULL,
    ADD CONSTRAINT certificate_assets_deleted_actor_085_check CHECK (
        (deleted_by_scope_id IS NULL AND deleted_by_user_id IS NULL) OR
        (deleted_by_scope_id IS NOT NULL AND deleted_by_user_id IS NOT NULL)
    );
ALTER TABLE certificate_asset_versions ALTER COLUMN actor_scope_id SET NOT NULL;
ALTER TABLE certificate_asset_private_key_envelope_facts ALTER COLUMN actor_scope_id SET NOT NULL;
ALTER TABLE certificate_asset_activation_facts ALTER COLUMN actor_scope_id SET NOT NULL;
ALTER TABLE certificate_asset_revocation_facts ALTER COLUMN actor_scope_id SET NOT NULL;
ALTER TABLE certificate_site_binding_facts ALTER COLUMN actor_scope_id SET NOT NULL;
ALTER TABLE certificate_asset_write_requests ALTER COLUMN actor_scope_id SET NOT NULL;

DO $$
DECLARE
    target record;
    constraint_name name;
    tenant_attnum smallint;
    actor_attnum smallint;
BEGIN
    FOR target IN SELECT * FROM (VALUES
        ('certificate_assets', 'created_by_user_id'),
        ('certificate_assets', 'updated_by_user_id'),
        ('certificate_assets', 'deleted_by_user_id'),
        ('certificate_asset_versions', 'imported_by_user_id'),
        ('certificate_asset_private_key_envelope_facts', 'changed_by_user_id'),
        ('certificate_asset_activation_facts', 'activated_by_user_id'),
        ('certificate_asset_revocation_facts', 'revoked_by_user_id'),
        ('certificate_site_binding_facts', 'changed_by_user_id'),
        ('certificate_asset_write_requests', 'actor_user_id')
    ) AS actor_fk(table_name, user_column) LOOP
        SELECT attnum INTO tenant_attnum FROM pg_attribute
        WHERE attrelid = to_regclass(target.table_name) AND attname = 'tenant_scope_id' AND NOT attisdropped;
        SELECT attnum INTO actor_attnum FROM pg_attribute
        WHERE attrelid = to_regclass(target.table_name) AND attname = target.user_column AND NOT attisdropped;
        SELECT constraint_row.conname INTO constraint_name
        FROM pg_constraint constraint_row
        WHERE constraint_row.conrelid = to_regclass(target.table_name)
          AND constraint_row.contype = 'f'
          AND constraint_row.confrelid = 'memberships'::regclass
          AND constraint_row.conkey = ARRAY[tenant_attnum, actor_attnum]::smallint[];
        IF constraint_name IS NULL THEN
            RAISE EXCEPTION 'certificate asset legacy actor foreign key is missing on %.%',
                target.table_name, target.user_column USING ERRCODE = 'P8500';
        END IF;
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', target.table_name, constraint_name);
    END LOOP;
END;
$$;

ALTER TABLE certificate_assets
    ADD CONSTRAINT certificate_assets_created_actor_085_fk
        FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_assets_updated_actor_085_fk
        FOREIGN KEY (updated_by_scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_assets_deleted_actor_085_fk
        FOREIGN KEY (deleted_by_scope_id, deleted_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_versions
    ADD CONSTRAINT certificate_asset_versions_actor_085_fk
        FOREIGN KEY (actor_scope_id, imported_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_private_key_envelope_facts
    ADD CONSTRAINT certificate_asset_envelope_actor_085_fk
        FOREIGN KEY (actor_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_activation_facts
    ADD CONSTRAINT certificate_asset_activation_actor_085_fk
        FOREIGN KEY (actor_scope_id, activated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_revocation_facts
    ADD CONSTRAINT certificate_asset_revocation_actor_085_fk
        FOREIGN KEY (actor_scope_id, revoked_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_site_binding_facts
    ADD CONSTRAINT certificate_site_binding_actor_085_fk
        FOREIGN KEY (actor_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_actor_085_fk
        FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DO $$
DECLARE
    constraint_name name;
BEGIN
    SELECT constraint_row.conname INTO constraint_name
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'certificate_asset_write_requests'::regclass
      AND constraint_row.contype = 'u'
      AND pg_get_constraintdef(constraint_row.oid) =
          'UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key)';
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'certificate asset legacy idempotency constraint is missing'
            USING ERRCODE = 'P8500';
    END IF;
    EXECUTE format('ALTER TABLE certificate_asset_write_requests DROP CONSTRAINT %I', constraint_name);
END;
$$;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_actor_idempotency_085_key
        UNIQUE (tenant_scope_id, actor_scope_id, actor_user_id, operation, idempotency_key);

CREATE FUNCTION validate_certificate_asset_actor_target_085()
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

CREATE TRIGGER certificate_assets_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_asset_versions_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_asset_versions
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_asset_envelopes_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_asset_private_key_envelope_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_asset_activations_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_asset_activation_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_asset_revocations_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_asset_revocation_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_site_bindings_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_site_binding_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();
CREATE TRIGGER certificate_asset_writes_actor_target_085
BEFORE INSERT OR UPDATE ON certificate_asset_write_requests
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_actor_target_085();

CREATE OR REPLACE FUNCTION protect_certificate_asset()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'certificate assets cannot be physically removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL
           OR NEW.deleted_by_scope_id IS NOT NULL THEN
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
       OR NEW.created_by_scope_id IS DISTINCT FROM OLD.created_by_scope_id
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
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
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
