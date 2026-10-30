-- 521（r136 proto-batch）：网站协议批量设置改为直接批量写站点的 http2_enabled/http3_enabled/
-- tls_prefer_server_ciphers（512，POST /v1/sites/batch-action action=set_protocols）。136 的批次/状态/
-- 投递表只被已删除的 siteprotocolcontrol 读写，发布端从不读取，节点也没有消费者，这里整体删除。
-- 权限码 site_protocols.read/manage 一并删除（主会话 merge-p9 定）：先删系统角色的授权，再删 136 的授权触发器
-- 与函数、自定义权限目录与权限码。自定义角色（含历史修订）引用过它们时拒绝（P5212），由管理员先处理。
-- 分支占位 550，merge-p9 改为 521、前驱 520。
LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    custom_role_revisions, site_protocol_batches, site_protocol_states, site_protocol_batch_items,
    site_protocol_jobs, site_protocol_node_results, site_protocol_write_requests, site_protocol_outbox,
    site_protocol_audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_521_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 520 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=520 AND
        migration_id='520_site_tls_custom_cipher_suites' AND
        checksum_sha256='c4459582720eb002b6c2dd65a3685c6c36e2c090f9b91ab22f07fee22e9a9247' AND
        down_checksum_sha256='6f4c66fd0916c0c04c0ed5f8d33552cdea250f52ed5033bbee83e5834abe12c7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_protocol_batches') IS NULL THEN
        RAISE EXCEPTION 'migration 521 requires the exact verified 520 head' USING ERRCODE='P5210';
    END IF;
END;
$migration_521_up$;

DO $migration_521_permissions$
BEGIN
    IF EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY['site_protocols.read','site_protocols.manage']::text[]
    ) OR EXISTS (
        SELECT 1 FROM role_permissions grant_row JOIN roles role ON role.id=grant_row.role_id
        WHERE NOT role.system_role AND grant_row.permission_name IN ('site_protocols.read','site_protocols.manage')
    ) THEN
        RAISE EXCEPTION 'custom roles reference site_protocols.read/manage; remove them before 521'
            USING ERRCODE='P5212';
    END IF;
END;
$migration_521_permissions$;

-- 系统角色上目录内权限的删除被 role_permissions_system_role_guard 拦住（042），只在本事务内临时停用。
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name IN ('site_protocols.read','site_protocols.manage');
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DROP TRIGGER roles_site_protocol_permissions_136 ON roles;
DROP FUNCTION grant_site_protocol_permissions_136();
DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('site_protocols.read','site_protocols.manage');
DELETE FROM permissions WHERE name IN ('site_protocols.read','site_protocols.manage');

-- 批次只记录"想要"的 HTTP/3 状态，从未生效；站点真实状态在 sites 三列，不迁移。
DROP TRIGGER site_protocol_audit_truncate_136 ON site_protocol_audit_events;
DROP TRIGGER site_protocol_audit_guard_136 ON site_protocol_audit_events;
DROP TRIGGER site_protocol_receipts_guard_136 ON site_protocol_write_requests;
DROP TRIGGER site_protocol_outbox_guard_136 ON site_protocol_outbox;
DROP TRIGGER site_protocol_node_results_guard_136_del ON site_protocol_node_results;
DROP TRIGGER site_protocol_node_results_guard_136 ON site_protocol_node_results;
DROP TRIGGER site_protocol_items_guard_136 ON site_protocol_batch_items;
DROP TRIGGER site_protocol_states_guard_136 ON site_protocol_states;
DROP TRIGGER site_protocol_batches_guard_136 ON site_protocol_batches;
DROP TRIGGER site_protocol_items_scope_136 ON site_protocol_batch_items;
DROP TRIGGER site_protocol_node_results_scope_136 ON site_protocol_node_results;
DROP TRIGGER site_protocol_states_scope_136 ON site_protocol_states;
DROP TRIGGER site_protocol_batches_scope_136 ON site_protocol_batches;

DROP TABLE site_protocol_audit_events;
DROP TABLE site_protocol_outbox;
DROP TABLE site_protocol_write_requests;
DROP TABLE site_protocol_node_results;
DROP TABLE site_protocol_jobs;
DROP TABLE site_protocol_states;
DROP TABLE site_protocol_batch_items;
DROP TABLE site_protocol_batches;

DROP FUNCTION guard_site_protocol_append_only_136();
DROP FUNCTION guard_site_protocol_receipt_136();
DROP FUNCTION guard_site_protocol_outbox_136();
DROP FUNCTION guard_site_protocol_node_result_136();
DROP FUNCTION guard_site_protocol_item_136();
DROP FUNCTION guard_site_protocol_state_136();
DROP FUNCTION guard_site_protocol_batch_136();
DROP FUNCTION validate_site_protocol_scope_136();
