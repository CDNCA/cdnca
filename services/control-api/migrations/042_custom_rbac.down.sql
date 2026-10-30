LOCK TABLE custom_rbac_permission_catalog,
    custom_rbac_system_role_permission_additions,
    custom_roles,
    custom_role_revisions,
    custom_role_deactivations,
    custom_role_grants,
    custom_role_grant_revocations,
    custom_rbac_write_requests,
    mfa_step_up_uses,
    roles,
    role_permissions,
    role_assignments,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM custom_roles) OR
       EXISTS (SELECT 1 FROM custom_role_revisions) OR
       EXISTS (SELECT 1 FROM custom_role_deactivations) OR
       EXISTS (SELECT 1 FROM custom_role_grants) OR
       EXISTS (SELECT 1 FROM custom_role_grant_revocations) OR
       EXISTS (SELECT 1 FROM custom_rbac_write_requests) OR
       EXISTS (SELECT 1 FROM mfa_step_up_uses WHERE resource_binding_sha256 IS NOT NULL) OR
       EXISTS (SELECT 1 FROM audit_events WHERE action LIKE 'identity.custom_role.%') THEN
        RAISE EXCEPTION 'custom RBAC business facts prevent migration 042 rollback'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER custom_rbac_audit_no_truncate ON audit_events;

DROP TRIGGER role_assignments_custom_rbac_lock ON role_assignments;
DROP FUNCTION lock_custom_rbac_identity_assignment();
DROP TRIGGER roles_tenant_owner_custom_rbac_manage ON roles;
DROP FUNCTION grant_custom_rbac_manage_to_tenant_owner();
DROP TRIGGER role_permissions_system_role_guard ON role_permissions;
DROP FUNCTION guard_system_role_permission_mutation();
DROP TRIGGER roles_system_role_guard ON roles;
DROP FUNCTION guard_system_role_mutation();

DROP TRIGGER custom_roles_no_delete ON custom_roles;
DROP FUNCTION prevent_custom_role_removal();

DROP TRIGGER custom_role_grant_revocations_project_insert ON custom_role_grant_revocations;
DROP FUNCTION project_custom_role_revocation();
DROP TRIGGER custom_role_grants_project_insert ON custom_role_grants;
DROP FUNCTION project_custom_role_grant();
DROP TRIGGER custom_roles_project_update ON custom_roles;
DROP FUNCTION project_custom_role_update();
DROP TRIGGER custom_roles_project_insert ON custom_roles;
DROP FUNCTION project_custom_role_insert();
DROP TRIGGER custom_rbac_permission_catalog_delete_guard ON custom_rbac_permission_catalog;
DROP TRIGGER custom_rbac_permission_catalog_no_update_or_truncate ON custom_rbac_permission_catalog;
DROP FUNCTION protect_custom_rbac_permission_catalog();
DROP TRIGGER custom_rbac_write_requests_append_only ON custom_rbac_write_requests;
DROP TRIGGER custom_role_grant_revocations_append_only ON custom_role_grant_revocations;
DROP TRIGGER custom_role_grants_append_only ON custom_role_grants;
DROP TRIGGER custom_role_deactivations_append_only ON custom_role_deactivations;
DROP TRIGGER custom_role_revisions_append_only ON custom_role_revisions;
DROP FUNCTION prevent_custom_rbac_fact_mutation();

DROP TRIGGER custom_role_grant_revocations_validate ON custom_role_grant_revocations;
DROP FUNCTION validate_custom_role_revocation();
DROP TRIGGER custom_role_grants_validate ON custom_role_grants;
DROP FUNCTION validate_custom_role_grant();
DROP TRIGGER custom_role_deactivations_apply ON custom_role_deactivations;
DROP FUNCTION apply_custom_role_deactivation();
DROP TRIGGER custom_role_deactivations_validate ON custom_role_deactivations;
DROP FUNCTION validate_custom_role_deactivation();
DROP TRIGGER custom_roles_projection_guard ON custom_roles;
DROP FUNCTION validate_custom_role_projection();
DROP TRIGGER custom_role_revisions_validate ON custom_role_revisions;
DROP FUNCTION validate_custom_role_revision();
DROP FUNCTION custom_rbac_actor_can_manage(uuid, uuid);
DROP FUNCTION custom_rbac_effective_permissions(uuid, uuid);

DELETE FROM role_assignments
WHERE role_id IN (SELECT id FROM custom_roles);
DELETE FROM role_permissions
WHERE role_id IN (SELECT id FROM custom_roles);
DELETE FROM roles
WHERE id IN (SELECT id FROM custom_roles);

DROP TABLE custom_rbac_write_requests;
DROP TABLE custom_role_grant_revocations;
DROP TABLE custom_role_grants;
DROP TABLE custom_role_deactivations;
DROP TABLE custom_role_revisions;
DROP TABLE custom_roles;

DELETE FROM role_permissions permission
USING custom_rbac_system_role_permission_additions addition
WHERE permission.role_id = addition.role_id AND
      permission.permission_name = addition.permission_name;
DROP TABLE custom_rbac_system_role_permission_additions;
DROP TABLE custom_rbac_permission_catalog;

ALTER TABLE mfa_step_up_uses DROP COLUMN resource_binding_sha256;
