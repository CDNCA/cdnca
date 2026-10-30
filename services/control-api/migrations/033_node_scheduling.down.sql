LOCK TABLE
    node_scheduling_write_requests,
    node_line_groups,
    node_line_group_revisions,
    node_line_endpoints,
    node_line_endpoint_health
IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM node_line_groups)
       OR EXISTS (SELECT 1 FROM node_line_group_revisions)
       OR EXISTS (SELECT 1 FROM node_line_endpoints)
       OR EXISTS (SELECT 1 FROM node_line_endpoint_health)
       OR EXISTS (SELECT 1 FROM node_scheduling_write_requests) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'node scheduling facts exist; migration 033 rollback refused';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS node_line_group_revisions_health_complete ON node_line_group_revisions;
DROP FUNCTION IF EXISTS assert_node_line_group_revision_health_complete();
DROP TRIGGER IF EXISTS node_line_endpoint_health_prevent_truncate ON node_line_endpoint_health;
DROP TRIGGER IF EXISTS node_line_endpoint_health_monotonic ON node_line_endpoint_health;
DROP FUNCTION IF EXISTS protect_node_line_endpoint_health();
DROP TRIGGER IF EXISTS node_line_groups_current_snapshot ON node_line_groups;
DROP FUNCTION IF EXISTS assert_node_line_group_current_snapshot();
DROP TRIGGER IF EXISTS node_line_endpoints_prevent_truncate ON node_line_endpoints;
DROP TRIGGER IF EXISTS node_line_endpoints_immutable ON node_line_endpoints;
DROP FUNCTION IF EXISTS protect_node_line_endpoint();
DROP TRIGGER IF EXISTS node_line_group_revisions_prevent_truncate ON node_line_group_revisions;
DROP TRIGGER IF EXISTS node_line_group_revisions_immutable ON node_line_group_revisions;
DROP FUNCTION IF EXISTS protect_node_line_group_revision();
DROP TRIGGER IF EXISTS node_line_groups_prevent_truncate ON node_line_groups;
DROP TRIGGER IF EXISTS node_line_groups_protect_revision ON node_line_groups;
DROP FUNCTION IF EXISTS protect_node_line_group();

DROP TRIGGER IF EXISTS node_scheduling_write_requests_prevent_truncate ON node_scheduling_write_requests;
DROP TRIGGER IF EXISTS node_scheduling_write_requests_state ON node_scheduling_write_requests;
DROP FUNCTION IF EXISTS protect_node_scheduling_write_request();

DROP TABLE IF EXISTS node_scheduling_write_requests;
DROP TABLE IF EXISTS node_line_endpoint_health;
ALTER TABLE node_line_groups DROP CONSTRAINT IF EXISTS node_line_groups_current_revision_fk;
DROP TABLE IF EXISTS node_line_endpoints;
DROP TABLE IF EXISTS node_line_group_revisions;
DROP TRIGGER IF EXISTS node_line_groups_tenant_scope ON node_line_groups;
DROP TABLE IF EXISTS node_line_groups;
DROP FUNCTION IF EXISTS assert_node_scheduling_tenant_scope();

DROP TRIGGER IF EXISTS roles_node_scheduling_permissions ON roles;
DROP FUNCTION IF EXISTS grant_node_scheduling_permissions_to_system_role();

DELETE FROM role_permissions
WHERE permission_name IN ('node_scheduling.read', 'node_scheduling.manage');
DELETE FROM permissions
WHERE name IN ('node_scheduling.read', 'node_scheduling.manage');
