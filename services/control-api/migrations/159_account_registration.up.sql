LOCK TABLE schema_migrations,users IN ACCESS EXCLUSIVE MODE;

DO $migration_159$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>158 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>158 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=158 AND migration_id='158_ja4_block_edge_receipts' AND
              checksum_sha256='8d465893298a1641767ec0ec776660082c7e035c96eaa24eb90f14c136b792b4' AND
              down_checksum_sha256='dace062a3bcc560a8ed8a7ac9e4718ff59acdb9b71ebd8fc84c9d270b3210b0a' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('account_registration_requests_159') IS NOT NULL OR
         to_regclass('account_registration_terms_159') IS NOT NULL OR
         to_regclass('account_registration_verification_intents_159') IS NOT NULL OR
         to_regclass('users_email_registration_unique_159') IS NOT NULL OR
         to_regclass('users_phone_registration_unique_159') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 159 requires a contiguous verified 158 release head'
            USING ERRCODE='P1590';
    END IF;
    IF EXISTS (
        SELECT 1 FROM users WHERE email IS NOT NULL GROUP BY email HAVING count(*)>1
    ) OR EXISTS (
        SELECT 1 FROM users WHERE phone IS NOT NULL GROUP BY phone HAVING count(*)>1
    ) THEN
        RAISE EXCEPTION 'migration 159 requires unique normalized account identities'
            USING ERRCODE='P1591';
    END IF;
END;
$migration_159$;

CREATE UNIQUE INDEX users_email_registration_unique_159
    ON users(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_phone_registration_unique_159
    ON users(phone) WHERE phone IS NOT NULL;

CREATE TABLE account_registration_requests_159 (
    id uuid PRIMARY KEY,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    state text NOT NULL CHECK(state IN ('pending','completed')),
    outcome text CHECK(outcome IS NULL OR outcome IN ('created','duplicate')),
    tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    response_status integer CHECK(response_status IS NULL OR response_status=202),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    completed_at timestamptz CHECK(completed_at IS NULL OR (isfinite(completed_at) AND completed_at>=created_at)),
    UNIQUE(idempotency_key),
    UNIQUE(id,scope_id,user_id),
    CHECK(
        (state='pending' AND outcome IS NULL AND tenant_id IS NULL AND scope_id IS NULL AND
         user_id IS NULL AND response_status IS NULL AND completed_at IS NULL) OR
        (state='completed' AND response_status=202 AND completed_at IS NOT NULL AND (
            (outcome='created' AND tenant_id IS NOT NULL AND scope_id IS NOT NULL AND user_id IS NOT NULL) OR
            (outcome='duplicate' AND tenant_id IS NULL AND scope_id IS NULL AND user_id IS NULL)
        ))
    )
);

CREATE TABLE account_registration_terms_159 (
    registration_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    terms_version text NOT NULL CHECK(terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    accepted_at timestamptz NOT NULL CHECK(isfinite(accepted_at)),
    FOREIGN KEY(registration_id,scope_id,user_id)
        REFERENCES account_registration_requests_159(id,scope_id,user_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE account_registration_verification_intents_159 (
    id uuid PRIMARY KEY,
    registration_id uuid NOT NULL UNIQUE,
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    verification_channel text NOT NULL CHECK(verification_channel IN ('email','sms')),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    FOREIGN KEY(registration_id,scope_id,user_id)
        REFERENCES account_registration_requests_159(id,scope_id,user_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION guard_account_registration_request_159()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR OLD.state<>'pending' OR NEW.state<>'completed' OR
       NEW.id IS DISTINCT FROM OLD.id OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
       NEW.subject_digest IS DISTINCT FROM OLD.subject_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'account registration receipt mutation rejected' USING ERRCODE='P1592';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_account_registration_fact_159()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'account registration facts are immutable' USING ERRCODE='P1592';
END;
$$;

CREATE FUNCTION prevent_account_registration_truncate_159()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'account registration facts cannot be truncated' USING ERRCODE='P1592';
END;
$$;

CREATE TRIGGER account_registration_request_guard_159
BEFORE UPDATE OR DELETE ON account_registration_requests_159
FOR EACH ROW EXECUTE FUNCTION guard_account_registration_request_159();
CREATE TRIGGER account_registration_terms_guard_159
BEFORE UPDATE OR DELETE ON account_registration_terms_159
FOR EACH ROW EXECUTE FUNCTION guard_account_registration_fact_159();
CREATE TRIGGER account_registration_verification_guard_159
BEFORE UPDATE OR DELETE ON account_registration_verification_intents_159
FOR EACH ROW EXECUTE FUNCTION guard_account_registration_fact_159();
CREATE TRIGGER account_registration_request_truncate_159
BEFORE TRUNCATE ON account_registration_requests_159
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_registration_truncate_159();
CREATE TRIGGER account_registration_terms_truncate_159
BEFORE TRUNCATE ON account_registration_terms_159
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_registration_truncate_159();
CREATE TRIGGER account_registration_verification_truncate_159
BEFORE TRUNCATE ON account_registration_verification_intents_159
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_registration_truncate_159();

REVOKE ALL ON account_registration_requests_159 FROM PUBLIC;
REVOKE ALL ON account_registration_terms_159 FROM PUBLIC;
REVOKE ALL ON account_registration_verification_intents_159 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_account_registration_request_159() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_account_registration_fact_159() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_account_registration_truncate_159() FROM PUBLIC;
