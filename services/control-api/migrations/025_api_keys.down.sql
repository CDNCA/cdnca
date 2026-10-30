DROP TABLE api_key_write_requests;
DROP TABLE api_keys;

DROP FUNCTION protect_api_key_write_request();
DROP FUNCTION protect_api_key_lifecycle();

ALTER TABLE access_scopes
    DROP CONSTRAINT access_scopes_id_tenant_unique;

DELETE FROM role_permissions
WHERE permission_name IN ('api_keys.self.manage', 'api_keys.admin.manage');

DELETE FROM permissions
WHERE name IN ('api_keys.self.manage', 'api_keys.admin.manage');
