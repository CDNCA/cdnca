LOCK TABLE schema_migrations, identity_user_login_security, identity_write_requests, account_login_challenges_197 IN ACCESS EXCLUSIVE MODE;

DO $migration_252_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 252 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 252 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=252 AND migration_id='252_identity_user_login_security' AND checksum_sha256='11333ecc36f8789b6783744e0f0aa18bac7aac536be88a0fa66de496b0d3a911' AND integrity_state='verified'
    ) OR EXISTS (SELECT 1 FROM identity_user_login_security) OR
       EXISTS (SELECT 1 FROM identity_write_requests WHERE operation='identity.user.login_security.update') OR
       EXISTS (SELECT 1 FROM account_login_challenges_197 WHERE login_security_revision <> 0) THEN
        RAISE EXCEPTION 'migration 252 rollback requires an unused login security schema; preserve policy and receipts and deploy a compatible authentication binary' USING ERRCODE='P2521';
    END IF;
END;
$migration_252_down$;

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create','identity.user.update','identity.self.update','identity.membership.suspend',
        'identity.user.password.reset','identity.user.delete'
    ));
ALTER TABLE account_login_challenges_197 DROP COLUMN login_security_revision;
DROP TABLE identity_user_login_security;
