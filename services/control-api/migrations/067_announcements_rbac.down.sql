LOCK TABLE access_scopes,
    roles,
    role_permissions,
    permissions,
    custom_rbac_permission_catalog,
    custom_role_revisions,
    announcement_rbac_system_role_grant_additions,
    announcements,
    announcement_versions,
    announcement_audience_users,
    announcement_audience_groups,
    announcement_recipient_snapshots,
    announcement_inbox_events,
    announcement_inbox_states,
    announcement_write_requests,
    announcement_state_facts,
    announcement_state_watermarks,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM permissions
        WHERE name IN ('announcements.read', 'announcements.manage')) <> 2 OR
       (SELECT count(*) FROM custom_rbac_permission_catalog
        WHERE permission_name IN ('announcements.read', 'announcements.manage')
          AND NOT step_up_required) <> 2 THEN
        RAISE EXCEPTION 'migration 067 announcement permission catalog drift prevents rollback'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        WHERE permission.permission_name IN ('announcements.read', 'announcements.manage')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions revision
        WHERE revision.permissions && ARRAY[
            'announcements.read', 'announcements.manage'
        ]::text[]
    ) OR EXISTS (SELECT 1 FROM announcements)
       OR EXISTS (SELECT 1 FROM announcement_versions)
       OR EXISTS (SELECT 1 FROM announcement_audience_users)
       OR EXISTS (SELECT 1 FROM announcement_audience_groups)
       OR EXISTS (SELECT 1 FROM announcement_recipient_snapshots)
       OR EXISTS (SELECT 1 FROM announcement_inbox_events)
       OR EXISTS (SELECT 1 FROM announcement_inbox_states)
       OR EXISTS (SELECT 1 FROM announcement_write_requests)
       OR EXISTS (SELECT 1 FROM announcement_state_facts)
       OR EXISTS (SELECT 1 FROM announcement_state_watermarks WHERE current_watermark <> 0)
       OR EXISTS (SELECT 1 FROM audit_events WHERE action LIKE 'announcement.%')
       OR EXISTS (
            SELECT 1
            FROM role_permissions permission
            JOIN roles role ON role.id = permission.role_id
            LEFT JOIN announcement_rbac_system_role_grant_additions addition
              ON addition.role_id = permission.role_id
             AND addition.permission_name = permission.permission_name
             AND addition.source_migration = 67
            WHERE permission.permission_name IN ('announcements.read', 'announcements.manage')
              AND role.system_role AND addition.role_id IS NULL
       ) OR EXISTS (
            SELECT 1
            FROM announcement_rbac_system_role_grant_additions addition
            JOIN roles role ON role.id = addition.role_id
            JOIN access_scopes scope ON scope.id = role.scope_id
            WHERE addition.source_migration <> 67 OR NOT role.system_role OR scope.kind <> 'tenant'
               OR NOT (
                    (role.name = 'tenant_owner' AND addition.permission_name IN (
                        'announcements.read', 'announcements.manage'
                    )) OR
                    (role.name = 'tenant_viewer' AND
                     addition.permission_name = 'announcements.read')
               )
       ) THEN
        RAISE EXCEPTION 'announcement RBAC facts prevent migration 067 rollback'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER announcement_rbac_catalog_delete_guard_067
    ON custom_rbac_permission_catalog;
DROP FUNCTION protect_announcement_rbac_catalog_delete_067();
DROP TRIGGER roles_project_announcement_permissions_067 ON roles;
DROP FUNCTION project_announcement_system_role_permissions_067();
DROP TRIGGER access_scopes_protect_announcement_classification_067 ON access_scopes;
DROP FUNCTION protect_announcement_rbac_scope_classification_067();
DROP TRIGGER announcement_rbac_grant_additions_no_truncate
    ON announcement_rbac_system_role_grant_additions;
DROP TRIGGER announcement_rbac_grant_additions_protect
    ON announcement_rbac_system_role_grant_additions;
DROP FUNCTION protect_announcement_rbac_grant_addition_067();

ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions permission
USING announcement_rbac_system_role_grant_additions addition
WHERE permission.role_id = addition.role_id
  AND permission.permission_name = addition.permission_name
  AND addition.source_migration = 67;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE announcement_rbac_system_role_grant_additions;
