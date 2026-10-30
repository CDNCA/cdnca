INSERT INTO permissions (name, description) VALUES
    ('jobs.read', 'Read background jobs in the authenticated tenant scope'),
    ('jobs.read_all', 'Read background jobs across tenant scopes');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('jobs.read', false),
    ('jobs.read_all', false);

CREATE INDEX background_jobs_global_created_idx
    ON background_jobs (created_at DESC, id DESC);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'jobs.read_all'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
WHERE role.system_role AND scope.kind = 'platform' AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'jobs.read'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
WHERE role.system_role AND scope.kind = 'tenant'
  AND role.name IN ('tenant_owner', 'tenant_viewer')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_job_query_permissions_057()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO scope_kind FROM access_scopes WHERE id = NEW.scope_id;
    IF scope_kind = 'platform' AND NEW.name = 'platform_owner' THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'jobs.read_all')
        ON CONFLICT DO NOTHING;
    ELSIF scope_kind = 'tenant' AND NEW.name IN ('tenant_owner', 'tenant_viewer') THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'jobs.read')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_job_query_permissions_057
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_job_query_permissions_057();
