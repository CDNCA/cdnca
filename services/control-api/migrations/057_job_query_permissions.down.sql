DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        WHERE permission.permission_name IN ('jobs.read', 'jobs.read_all')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY['jobs.read', 'jobs.read_all']::text[]
    ) THEN
        RAISE EXCEPTION 'migration 057 job query permissions are referenced by custom RBAC facts';
    END IF;
END;
$$;

DROP TRIGGER roles_job_query_permissions_057 ON roles;
DROP FUNCTION grant_job_query_permissions_057();

DROP INDEX background_jobs_global_created_idx;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('jobs.read', 'jobs.read_all');
DELETE FROM role_permissions
WHERE permission_name IN ('jobs.read', 'jobs.read_all');
DELETE FROM permissions
WHERE name IN ('jobs.read', 'jobs.read_all');
