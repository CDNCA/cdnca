DROP TABLE IF EXISTS control_upgrade_check_requests;
DELETE FROM role_permissions WHERE permission_name = 'control.upgrades.check';
DELETE FROM permissions WHERE name = 'control.upgrades.check';
