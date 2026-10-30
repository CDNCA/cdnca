DROP TABLE IF EXISTS node_write_requests;

DELETE FROM role_permissions WHERE permission_name IN ('nodes.read', 'nodes.manage');
DELETE FROM permissions WHERE name IN ('nodes.read', 'nodes.manage');
