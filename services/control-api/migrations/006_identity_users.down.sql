DROP INDEX IF EXISTS users_status_created_idx;
DROP TABLE IF EXISTS identity_write_requests;

DELETE FROM role_permissions
WHERE permission_name IN ('identity.self.update', 'identity.password.change');

DELETE FROM permissions
WHERE name IN ('identity.self.update', 'identity.password.change');

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_phone_normalized_check,
    DROP CONSTRAINT IF EXISTS users_email_normalized_check,
    DROP COLUMN IF EXISTS phone,
    DROP COLUMN IF EXISTS email;
