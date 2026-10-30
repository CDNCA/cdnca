DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM challenge_policy_revisions)
       OR EXISTS (SELECT 1 FROM challenge_policy_write_requests) THEN
        RAISE EXCEPTION 'migration 053 contains irreversible challenge policy facts';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        WHERE permission.permission_name IN ('challenge_policies.read', 'challenge_policies.manage')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY['challenge_policies.read', 'challenge_policies.manage']::text[]
    ) THEN
        RAISE EXCEPTION 'migration 053 challenge permissions are referenced by custom RBAC facts';
    END IF;
END;
$$;

DROP TRIGGER challenge_policy_revisions_audited_053 ON challenge_policy_revisions;
DROP FUNCTION assert_challenge_policy_revision_audited_053();
DROP TRIGGER challenge_policy_write_requests_no_truncate_053 ON challenge_policy_write_requests;
DROP TRIGGER challenge_policy_write_requests_guard_053 ON challenge_policy_write_requests;
DROP FUNCTION protect_challenge_policy_write_request_053();
DROP TRIGGER challenge_policy_revisions_no_truncate_053 ON challenge_policy_revisions;
DROP TRIGGER challenge_policy_revisions_append_only_053 ON challenge_policy_revisions;
DROP FUNCTION protect_challenge_policy_revision_053();
DROP TRIGGER challenge_policies_no_truncate_053 ON challenge_policies;
DROP TRIGGER challenge_policies_projection_guard_053 ON challenge_policies;
DROP FUNCTION protect_challenge_policy_projection_053();
DROP TRIGGER challenge_policy_revisions_project_053 ON challenge_policy_revisions;
DROP FUNCTION project_challenge_policy_revision_053();
DROP TRIGGER challenge_policy_revisions_validate_053 ON challenge_policy_revisions;
DROP FUNCTION validate_challenge_policy_revision_053();
DROP FUNCTION challenge_policy_actor_can_053(uuid, uuid, uuid, text);
DROP FUNCTION challenge_policy_bypass_valid_053(jsonb);
DROP FUNCTION challenge_policy_host_valid_053(text);

DROP TABLE challenge_policy_write_requests;
DROP TABLE challenge_policy_revisions;
DROP TABLE challenge_policies;

DROP TRIGGER roles_challenge_policy_permissions_053 ON roles;
DROP FUNCTION grant_challenge_policy_permissions_053();

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('challenge_policies.read', 'challenge_policies.manage');
DELETE FROM role_permissions
WHERE permission_name IN ('challenge_policies.read', 'challenge_policies.manage');
DELETE FROM permissions
WHERE name IN ('challenge_policies.read', 'challenge_policies.manage');
