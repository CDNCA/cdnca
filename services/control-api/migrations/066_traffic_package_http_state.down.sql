LOCK TABLE traffic_package_workload_bindings,
    traffic_package_workload_requests,
    traffic_package_product_catalog_watermarks,
    traffic_package_product_catalog_versions,
    tenant_traffic_package_usage_watermarks,
    traffic_package_usage_event_versions,
    tenant_traffic_package_state_watermarks,
    traffic_package_grant_state_versions,
    traffic_package_expire_requests,
    traffic_package_product_snapshots,
    traffic_package_events,
    traffic_package_grants,
    traffic_package_ledger_entries,
    audit_events,
    custom_role_revisions,
    custom_rbac_permission_catalog,
    roles,
    role_permissions,
    permissions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM traffic_package_workload_bindings)
       OR EXISTS (SELECT 1 FROM traffic_package_workload_requests)
       OR EXISTS (SELECT 1 FROM traffic_package_product_catalog_versions)
       OR EXISTS (SELECT 1 FROM traffic_package_usage_event_versions)
       OR EXISTS (SELECT 1 FROM traffic_package_grant_state_versions)
       OR EXISTS (SELECT 1 FROM traffic_package_expire_requests)
       OR EXISTS (
           SELECT 1 FROM traffic_package_events
           WHERE workload_binding_id IS NOT NULL OR workload_permission IS NOT NULL
              OR workload_cause IS NOT NULL OR workload_parent_request_id IS NOT NULL
       )
       OR EXISTS (
           SELECT 1 FROM traffic_package_ledger_entries
           WHERE workload_binding_id IS NOT NULL OR workload_permission IS NOT NULL
              OR workload_cause IS NOT NULL OR workload_parent_request_id IS NOT NULL
       )
       OR EXISTS (
           SELECT 1 FROM audit_events
           WHERE payload ? 'workload_binding_id' OR payload ? 'workload_permission'
              OR payload ? 'workload_cause' OR payload ? 'workload_parent_request_id'
              OR payload ? 'workload_parent_operation'
       )
       OR EXISTS (
           SELECT 1 FROM custom_role_revisions revision
           WHERE revision.permissions && ARRAY[
               'traffic_packages.read',
               'traffic_packages.manage',
               'traffic_packages.consume',
               'traffic_packages.usage_refund',
               'traffic_packages.expire',
               'traffic_packages.reverse'
           ]::text[]
       )
       OR EXISTS (
           SELECT 1
           FROM role_permissions permission
           JOIN roles role ON role.id = permission.role_id
           JOIN access_scopes scope ON scope.id = role.scope_id
           WHERE permission.permission_name IN (
               'traffic_packages.read',
               'traffic_packages.manage',
               'traffic_packages.consume',
               'traffic_packages.usage_refund',
               'traffic_packages.expire',
               'traffic_packages.reverse'
           ) AND NOT (
               role.system_role AND (
                   (scope.kind = 'platform' AND role.name = 'platform_owner'
                    AND permission.permission_name IN ('traffic_packages.read', 'traffic_packages.manage'))
                   OR
                   (scope.kind = 'tenant' AND role.name IN ('tenant_owner', 'tenant_viewer')
                    AND permission.permission_name = 'traffic_packages.read')
               )
           )
       ) THEN
        RAISE EXCEPTION 'traffic package HTTP facts prevent migration 066 rollback'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER traffic_package_expire_requests_binding_consistent ON traffic_package_expire_requests;
DROP FUNCTION assert_traffic_package_expire_request_binding();
DROP TRIGGER traffic_package_expire_requests_no_truncate ON traffic_package_expire_requests;
DROP TRIGGER traffic_package_expire_requests_protect ON traffic_package_expire_requests;
DROP FUNCTION protect_traffic_package_expire_request();
DROP TABLE traffic_package_expire_requests;

DROP TRIGGER audit_events_traffic_package_workload_consistent ON audit_events;
DROP FUNCTION assert_traffic_package_workload_audit();
DROP TRIGGER traffic_package_events_workload_consistent ON traffic_package_events;
DROP FUNCTION assert_traffic_package_workload_event();
DROP TRIGGER traffic_package_ledger_entries_workload_consistent ON traffic_package_ledger_entries;
DROP FUNCTION assert_traffic_package_workload_ledger_entry();

DROP TRIGGER traffic_package_workload_requests_consistent
    ON traffic_package_workload_requests;
DROP FUNCTION assert_traffic_package_workload_request();
DROP TRIGGER traffic_package_workload_requests_no_truncate
    ON traffic_package_workload_requests;
DROP TRIGGER traffic_package_workload_requests_protect
    ON traffic_package_workload_requests;
DROP FUNCTION protect_traffic_package_workload_request();
DROP TABLE traffic_package_workload_requests;

DROP TRIGGER traffic_package_product_snapshots_catalog_captured ON traffic_package_product_snapshots;
DROP TRIGGER traffic_package_product_catalog_versions_watermark_consistent
    ON traffic_package_product_catalog_versions;
DROP TRIGGER traffic_package_product_catalog_watermark_consistent
    ON traffic_package_product_catalog_watermarks;
DROP FUNCTION assert_traffic_package_product_catalog_watermark();

DROP TRIGGER traffic_package_events_usage_captured ON traffic_package_events;
DROP TRIGGER traffic_package_usage_event_versions_watermark_consistent
    ON traffic_package_usage_event_versions;
DROP TRIGGER tenant_traffic_package_usage_watermark_consistent
    ON tenant_traffic_package_usage_watermarks;
DROP FUNCTION assert_traffic_package_usage_watermark();

DROP TRIGGER traffic_package_grant_state_versions_watermark_consistent
    ON traffic_package_grant_state_versions;
DROP TRIGGER tenant_traffic_package_state_watermark_consistent
    ON tenant_traffic_package_state_watermarks;
DROP FUNCTION assert_traffic_package_state_watermark();

DROP TRIGGER traffic_package_product_catalog_watermarks_no_truncate
    ON traffic_package_product_catalog_watermarks;
DROP TRIGGER traffic_package_product_catalog_watermarks_protect
    ON traffic_package_product_catalog_watermarks;
DROP TRIGGER tenant_traffic_package_usage_watermarks_no_truncate
    ON tenant_traffic_package_usage_watermarks;
DROP TRIGGER tenant_traffic_package_usage_watermarks_protect
    ON tenant_traffic_package_usage_watermarks;
DROP TRIGGER tenant_traffic_package_state_watermarks_no_truncate
    ON tenant_traffic_package_state_watermarks;
DROP TRIGGER tenant_traffic_package_state_watermarks_protect
    ON tenant_traffic_package_state_watermarks;
DROP FUNCTION protect_traffic_package_watermark();

DROP TRIGGER traffic_package_grants_state_captured ON traffic_package_grants;
DROP FUNCTION assert_traffic_package_grant_state_captured();
DROP TRIGGER traffic_package_grant_state_versions_validate_source
    ON traffic_package_grant_state_versions;
DROP FUNCTION validate_traffic_package_grant_state_version();
DROP TRIGGER traffic_package_ledger_entries_append_state ON traffic_package_ledger_entries;
DROP FUNCTION append_traffic_package_grant_state_version();
DROP TRIGGER traffic_package_grant_state_versions_no_truncate
    ON traffic_package_grant_state_versions;
DROP TRIGGER traffic_package_grant_state_versions_append_only
    ON traffic_package_grant_state_versions;
DROP TABLE traffic_package_grant_state_versions;
DROP TABLE tenant_traffic_package_state_watermarks;

DROP TRIGGER traffic_package_events_append_usage_version ON traffic_package_events;
DROP FUNCTION append_traffic_package_usage_event_version();
DROP TRIGGER traffic_package_usage_event_versions_no_truncate
    ON traffic_package_usage_event_versions;
DROP TRIGGER traffic_package_usage_event_versions_append_only
    ON traffic_package_usage_event_versions;
DROP TABLE traffic_package_usage_event_versions;
DROP TABLE tenant_traffic_package_usage_watermarks;

DROP TRIGGER traffic_package_product_snapshots_append_catalog_version
    ON traffic_package_product_snapshots;
DROP FUNCTION append_traffic_package_product_catalog_version();
DROP TRIGGER traffic_package_product_catalog_versions_no_truncate
    ON traffic_package_product_catalog_versions;
DROP TRIGGER traffic_package_product_catalog_versions_append_only
    ON traffic_package_product_catalog_versions;
DROP TABLE traffic_package_product_catalog_versions;
DROP TABLE traffic_package_product_catalog_watermarks;

DROP INDEX traffic_package_ledger_entries_workload_binding_idx;
DROP INDEX traffic_package_events_workload_binding_idx;
ALTER TABLE traffic_package_ledger_entries
    DROP CONSTRAINT traffic_package_ledger_entries_workload_source_check,
    DROP COLUMN workload_parent_request_id,
    DROP COLUMN workload_cause,
    DROP COLUMN workload_permission,
    DROP COLUMN workload_binding_id;
ALTER TABLE traffic_package_events
    DROP CONSTRAINT traffic_package_events_workload_source_check,
    DROP COLUMN workload_parent_request_id,
    DROP COLUMN workload_cause,
    DROP COLUMN workload_permission,
    DROP COLUMN workload_binding_id;

DROP FUNCTION traffic_package_workload_permission_for_operation(text);

DROP TRIGGER traffic_package_workload_bindings_no_truncate ON traffic_package_workload_bindings;
DROP TRIGGER traffic_package_workload_bindings_protect ON traffic_package_workload_bindings;
DROP FUNCTION protect_traffic_package_workload_binding();
DROP TABLE traffic_package_workload_bindings;
DROP FUNCTION valid_traffic_package_workload_permissions(text[]);

DROP TRIGGER roles_project_traffic_package_permissions ON roles;
DROP FUNCTION project_traffic_package_system_role_permissions();

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name = 'traffic_packages.read';
DELETE FROM role_permissions
WHERE permission_name IN (
    'traffic_packages.read',
    'traffic_packages.manage',
    'traffic_packages.consume',
    'traffic_packages.usage_refund',
    'traffic_packages.expire',
    'traffic_packages.reverse'
);
DELETE FROM permissions
WHERE name IN (
    'traffic_packages.read',
    'traffic_packages.manage',
    'traffic_packages.consume',
    'traffic_packages.usage_refund',
    'traffic_packages.expire',
    'traffic_packages.reverse'
);
