DROP TABLE security_policy_write_requests;
DROP TABLE security_policy_versions;
DROP TABLE security_policies;

DELETE FROM role_permissions
WHERE permission_name IN ('security_policies.read', 'security_policies.manage');

DELETE FROM permissions
WHERE name IN ('security_policies.read', 'security_policies.manage');
