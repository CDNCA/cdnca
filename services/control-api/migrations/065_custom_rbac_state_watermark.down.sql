LOCK TABLE custom_roles,
    custom_role_revisions,
    custom_role_deactivations,
    custom_role_grants,
    custom_role_grant_revocations,
    custom_rbac_write_requests,
    mfa_step_up_uses,
    roles,
    role_permissions,
    role_assignments,
    audit_events,
    custom_rbac_state_watermark
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
        RAISE EXCEPTION 'custom RBAC business facts prevent migration 065 rollback'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER custom_role_grant_revocations_assign_state_version ON custom_role_grant_revocations;
DROP TRIGGER custom_role_grants_assign_state_version ON custom_role_grants;
DROP TRIGGER custom_role_deactivations_assign_state_version ON custom_role_deactivations;
DROP TRIGGER custom_role_revisions_assign_state_version ON custom_role_revisions;
DROP TRIGGER custom_roles_protect_state_version ON custom_roles;
DROP TRIGGER custom_roles_assign_state_version ON custom_roles;

DROP FUNCTION protect_custom_role_created_state_version();
DROP FUNCTION assign_custom_rbac_fact_state_version();
DROP FUNCTION assign_custom_role_created_state_version();
DROP FUNCTION allocate_custom_rbac_state_version();

DROP INDEX custom_role_grant_revocations_state_version_idx;
DROP INDEX custom_role_grants_state_version_idx;
DROP INDEX custom_role_deactivations_state_version_idx;
DROP INDEX custom_role_revisions_state_version_idx;
DROP INDEX custom_roles_created_state_version_idx;

ALTER TABLE custom_role_grant_revocations DROP COLUMN state_version;
ALTER TABLE custom_role_grants DROP COLUMN state_version;
ALTER TABLE custom_role_deactivations DROP COLUMN state_version;
ALTER TABLE custom_role_revisions DROP COLUMN state_version;
ALTER TABLE custom_roles DROP COLUMN created_state_version;

DROP TABLE custom_rbac_state_watermark;
