LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    custom_role_revisions, waf_adapt_exclusions IN ACCESS EXCLUSIVE MODE;

DO $migration_429_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 429 OR
       (SELECT max(version) FROM schema_migrations) <> 429 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=429 AND
        migration_id='429_waf_adapt_permissions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 429 down requires the exact verified migration head' USING ERRCODE='P4291';
    END IF;
    -- A custom role that holds the permissions would silently lose them.
    IF EXISTS (SELECT 1 FROM custom_role_revisions
               WHERE permissions && ARRAY['waf_adapt.read', 'waf_adapt.manage']::text[]) THEN
        RAISE EXCEPTION 'migration 429 down refuses: custom roles hold waf_adapt permissions' USING ERRCODE='P4292';
    END IF;
END;
$migration_429_down$;

ALTER TABLE waf_adapt_exclusions DROP CONSTRAINT waf_adapt_exclusions_reject_reason_429, DROP COLUMN reject_reason;
DROP TRIGGER roles_waf_adapt_permissions_429 ON roles;
DROP FUNCTION grant_waf_adapt_permissions_429();

ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name IN ('waf_adapt.read', 'waf_adapt.manage');
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('waf_adapt.read', 'waf_adapt.manage');
DELETE FROM permissions WHERE name IN ('waf_adapt.read', 'waf_adapt.manage');
