DROP TABLE url_auth_policy_write_requests;
DROP TABLE url_auth_policy_versions;
DROP TABLE url_auth_policy_keys;
DROP TABLE url_auth_policies;

DELETE FROM role_permissions
WHERE permission_name IN ('url_auth_policies.read', 'url_auth_policies.manage');

DELETE FROM permissions
WHERE name IN ('url_auth_policies.read', 'url_auth_policies.manage');
