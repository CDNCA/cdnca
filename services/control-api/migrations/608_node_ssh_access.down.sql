-- 608 回退：撤掉 nodes.ssh 与 SSH 连接标签的三张表/列。记住的凭据与“仅允许主控 SSH”状态随之删除
-- （节点侧 nft 表不受影响：节点在没有主控确认时会自行撤销）。自定义角色仍引用 nodes.ssh 时拒绝回退。
LOCK TABLE schema_migrations, permissions, role_permissions, nodes, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_608_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 608 OR
       (SELECT max(version) FROM schema_migrations) <> 608 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=608 AND
        migration_id='608_node_ssh_access' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 608 down requires the exact verified migration head' USING ERRCODE='P6081';
    END IF;
    IF EXISTS (SELECT 1 FROM role_permissions WHERE permission_name = 'nodes.ssh') THEN
        RAISE EXCEPTION 'migration 608 down refuses roles still granted nodes.ssh' USING ERRCODE='P6082';
    END IF;
END;
$migration_608_down$;

DROP TABLE node_ssh_access;
ALTER TABLE node_ssh_install_jobs DROP COLUMN restrict_ssh;
DROP TABLE node_ssh_credentials;
DELETE FROM permissions WHERE name = 'nodes.ssh';
