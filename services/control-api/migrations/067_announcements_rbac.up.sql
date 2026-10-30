LOCK TABLE access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM permissions
        WHERE name IN ('announcements.read', 'announcements.manage')) <> 2 OR
       (SELECT count(*) FROM custom_rbac_permission_catalog
        WHERE permission_name IN ('announcements.read', 'announcements.manage')
          AND NOT step_up_required) <> 2 THEN
        RAISE EXCEPTION 'migration 067 requires the migration 043 announcement permission catalog'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE FUNCTION protect_announcement_rbac_catalog_delete_067()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.permission_name IN ('announcements.read', 'announcements.manage') THEN
        RAISE EXCEPTION 'migration 067 announcement RBAC catalog rows cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER announcement_rbac_catalog_delete_guard_067
BEFORE DELETE ON custom_rbac_permission_catalog
FOR EACH ROW EXECUTE FUNCTION protect_announcement_rbac_catalog_delete_067();
ALTER TABLE custom_rbac_permission_catalog
    ENABLE ALWAYS TRIGGER announcement_rbac_catalog_delete_guard_067;

CREATE TABLE announcement_rbac_system_role_grant_additions (
    role_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (
        permission_name IN ('announcements.read', 'announcements.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 67 CHECK (source_migration = 67),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE CASCADE
);

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, permission.name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    CROSS JOIN (VALUES
        ('announcements.read'),
        ('announcements.manage')
    ) AS permission(name)
    WHERE role.system_role AND scope.kind = 'tenant' AND role.name = 'tenant_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO announcement_rbac_system_role_grant_additions (role_id, permission_name)
SELECT role_id, permission_name FROM additions;

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, 'announcements.read'
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND scope.kind = 'tenant' AND role.name = 'tenant_viewer'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO announcement_rbac_system_role_grant_additions (role_id, permission_name)
SELECT role_id, permission_name FROM additions;

CREATE FUNCTION protect_announcement_rbac_grant_addition_067()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'announcement RBAC grant provenance is projection controlled';
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'announcement RBAC grant provenance is append-only';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER announcement_rbac_grant_additions_protect
BEFORE INSERT OR UPDATE OR DELETE ON announcement_rbac_system_role_grant_additions
FOR EACH ROW EXECUTE FUNCTION protect_announcement_rbac_grant_addition_067();
CREATE TRIGGER announcement_rbac_grant_additions_no_truncate
BEFORE TRUNCATE ON announcement_rbac_system_role_grant_additions
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_rbac_grant_addition_067();
ALTER TABLE announcement_rbac_system_role_grant_additions
    ENABLE ALWAYS TRIGGER announcement_rbac_grant_additions_protect;
ALTER TABLE announcement_rbac_system_role_grant_additions
    ENABLE ALWAYS TRIGGER announcement_rbac_grant_additions_no_truncate;

CREATE FUNCTION protect_announcement_rbac_scope_classification_067()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.kind, NEW.tenant_id) IS DISTINCT FROM ROW(OLD.kind, OLD.tenant_id) AND EXISTS (
        SELECT 1
        FROM roles role
        JOIN role_permissions permission ON permission.role_id = role.id
        WHERE role.scope_id = OLD.id AND role.system_role
          AND permission.permission_name IN ('announcements.read', 'announcements.manage')
    ) THEN
        RAISE EXCEPTION 'scope classification with announcement RBAC grants is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER access_scopes_protect_announcement_classification_067
BEFORE UPDATE OF kind, tenant_id ON access_scopes
FOR EACH ROW EXECUTE FUNCTION protect_announcement_rbac_scope_classification_067();
ALTER TABLE access_scopes
    ENABLE ALWAYS TRIGGER access_scopes_protect_announcement_classification_067;

CREATE FUNCTION project_announcement_system_role_permissions_067()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind
    FROM access_scopes
    WHERE id = NEW.scope_id
    FOR SHARE;
    IF target_scope_kind IS DISTINCT FROM 'tenant' OR
       NEW.name NOT IN ('tenant_owner', 'tenant_viewer') THEN
        RETURN NEW;
    END IF;

    WITH additions AS (
        INSERT INTO role_permissions (role_id, permission_name)
        SELECT NEW.id, permission.name
        FROM (VALUES
            ('announcements.read'),
            ('announcements.manage')
        ) AS permission(name)
        WHERE NEW.name = 'tenant_owner' OR permission.name = 'announcements.read'
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO announcement_rbac_system_role_grant_additions (role_id, permission_name)
    SELECT role_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_announcement_permissions_067
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_announcement_system_role_permissions_067();
