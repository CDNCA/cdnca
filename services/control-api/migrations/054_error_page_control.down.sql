LOCK TABLE error_page_assets, error_page_asset_scan_facts, error_page_rules,
    error_page_rule_revisions, error_page_publications, error_page_write_requests,
    custom_role_revisions, custom_rbac_permission_catalog, roles, role_permissions, permissions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM error_page_assets) OR
       EXISTS (SELECT 1 FROM error_page_rules) OR
       EXISTS (SELECT 1 FROM error_page_rule_revisions) OR
       EXISTS (SELECT 1 FROM error_page_asset_scan_facts) OR
       EXISTS (SELECT 1 FROM error_page_publications) OR
       EXISTS (SELECT 1 FROM error_page_write_requests) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot remove error page control schema while facts exist';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        WHERE permission.permission_name IN ('error_pages.read', 'error_pages.manage')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY['error_pages.read', 'error_pages.manage']::text[]
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot remove referenced error page RBAC permissions';
    END IF;
END;
$$;

DROP TRIGGER error_page_write_requests_no_truncate ON error_page_write_requests;
DROP TRIGGER error_page_assets_no_truncate ON error_page_assets;
DROP FUNCTION prevent_error_page_truncate();
DROP TRIGGER error_page_publications_append_only ON error_page_publications;
DROP TRIGGER error_page_asset_scan_facts_append_only ON error_page_asset_scan_facts;
DROP TRIGGER error_page_rule_revisions_append_only ON error_page_rule_revisions;
DROP TRIGGER error_page_rules_append_only ON error_page_rules;
DROP FUNCTION prevent_error_page_fact_mutation();
DROP TRIGGER error_page_write_requests_protected ON error_page_write_requests;
DROP FUNCTION protect_error_page_write_request();
DROP TRIGGER error_page_publications_validate ON error_page_publications;
DROP FUNCTION validate_error_page_publication();
DROP TRIGGER error_page_rule_revisions_validate ON error_page_rule_revisions;
DROP FUNCTION validate_error_page_rule_revision();
DROP TRIGGER error_page_rules_validate_insert ON error_page_rules;
DROP FUNCTION validate_error_page_rule_identity();
DROP TRIGGER error_page_asset_scan_facts_validate ON error_page_asset_scan_facts;
DROP FUNCTION validate_error_page_scan_fact();
DROP TRIGGER error_page_assets_protect_update ON error_page_assets;
DROP FUNCTION protect_error_page_asset_update();
DROP TRIGGER error_page_assets_validate_insert ON error_page_assets;
DROP FUNCTION validate_error_page_asset_insert();
DROP FUNCTION error_page_actor_has_permission(uuid, uuid, text);

DROP TABLE error_page_write_requests;
DROP TABLE error_page_publications;
DROP TABLE error_page_rule_revisions;
DROP TABLE error_page_rules;
DROP TABLE error_page_asset_scan_facts;
DROP TABLE error_page_assets;

DROP TRIGGER roles_error_page_permissions_054 ON roles;
DROP FUNCTION grant_error_page_permissions_054();

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('error_pages.read', 'error_pages.manage');
DELETE FROM role_permissions WHERE permission_name IN ('error_pages.read', 'error_pages.manage');
DELETE FROM permissions WHERE name IN ('error_pages.read', 'error_pages.manage');
