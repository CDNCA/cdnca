LOCK TABLE schema_migrations, memberships, identity_write_requests, account_login_challenges_197 IN ACCESS EXCLUSIVE MODE;

DO $migration_252$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 251 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 251 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=251 AND migration_id='251_identity_user_metadata'
          AND checksum_sha256='88a8577382a5aff3c70e737f0eea4ec9781d8b0d54f250a2442a4ed9d9b5bbd4'
          AND down_checksum_sha256='07fdf05af6ea279d35eab2f2312c2976dbbc28635acbc52086693e5970e641fc'
          AND integrity_state='verified'
    ) OR to_regclass(current_schema() || '.identity_user_login_security') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 252 requires the exact verified 251 head and untouched login security schema' USING ERRCODE='P2520';
    END IF;
END;
$migration_252$;

CREATE TABLE identity_user_login_security (
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    login_verification text NOT NULL CHECK (login_verification IN ('none','email','sms')),
    login_allowlist text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(login_allowlist) <= 32 AND array_position(login_allowlist,NULL) IS NULL),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (scope_id,user_id),
    FOREIGN KEY (scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

ALTER TABLE account_login_challenges_197
    ADD COLUMN login_security_revision bigint NOT NULL DEFAULT 0 CHECK (login_security_revision >= 0);

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create','identity.user.update','identity.self.update','identity.membership.suspend',
        'identity.user.password.reset','identity.user.delete','identity.user.login_security.update'
    ));

REVOKE ALL ON identity_user_login_security FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON identity_user_login_security TO cdnca_control_app;
