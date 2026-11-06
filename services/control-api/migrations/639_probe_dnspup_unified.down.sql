-- 639 回退：撤拨测统一能力的表、列、事件与 probes.dnspup.request。自定义角色或 API Key 仍引用该权限时拒绝回退。
LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    custom_role_revisions, api_keys, notification_event_policies, notification_templates, probe_dnspup_settings,
    probe_dnspup_write_requests, node_dnspup_probe_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_639_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 639 OR
       (SELECT max(version) FROM schema_migrations) <> 639 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=639 AND
        migration_id='639_probe_dnspup_unified' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 639 down requires the exact verified migration head' USING ERRCODE='P6391';
    END IF;
    IF EXISTS (SELECT 1 FROM custom_role_revisions WHERE 'probes.dnspup.request' = ANY(permissions)) OR
       EXISTS (SELECT 1 FROM api_keys WHERE 'probes.dnspup.request' = ANY(scopes)) OR
       EXISTS (SELECT 1 FROM probe_dnspup_write_requests WHERE operation IN ('purposes', 'overrides', 'diagnose')) THEN
        RAISE EXCEPTION 'migration 639 down refuses: probes.dnspup.request or 639 write records are in use'
            USING ERRCODE='P6392';
    END IF;
END;
$migration_639_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN ('node.dnspup.line_unreachable.zh-cn',
    'node.dnspup.line_recovered.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_event_policies WHERE event_type IN ('node.dnspup.line_unreachable', 'node.dnspup.line_recovered');

DROP TRIGGER roles_tenant_probes_dnspup_request_639 ON roles;
DROP FUNCTION grant_tenant_probes_dnspup_request_639();
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name = 'probes.dnspup.request';
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DROP TABLE tenant_system_role_grant_additions_639;
DELETE FROM custom_rbac_permission_catalog WHERE permission_name = 'probes.dnspup.request';
DELETE FROM permissions WHERE name = 'probes.dnspup.request';

ALTER TABLE probe_dnspup_write_requests DROP CONSTRAINT probe_dnspup_write_requests_operation_639_ck,
    ADD CONSTRAINT probe_dnspup_write_requests_operation_462_ck CHECK (operation IN ('settings', 'test', 'node_settings'));

DROP TABLE probe_dnspup_plugin_usage;
DROP TABLE probe_dnspup_plugin_requests;
ALTER TABLE probe_dnspup_settings DROP COLUMN plugin_per_minute, DROP COLUMN plugin_tenant_monthly;
DROP TABLE node_dnspup_line_alert_states;
DROP TABLE probe_dnspup_observations;
DROP TABLE probe_dnspup_usage;
DROP TABLE probe_dnspup_purposes;
DROP TABLE node_dnspup_probe_overrides;
ALTER TABLE node_dnspup_probe_settings DROP COLUMN probe_type, DROP COLUMN selection, DROP COLUMN line_alert_min_points,
    DROP COLUMN line_alert_rounds, DROP COLUMN auto_diagnose;
