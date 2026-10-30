DROP TABLE IF EXISTS site_write_requests;
DROP TABLE IF EXISTS sites;
DELETE FROM role_permissions WHERE permission_name IN ('sites.read', 'sites.manage');
DELETE FROM permissions WHERE name IN ('sites.read', 'sites.manage');
