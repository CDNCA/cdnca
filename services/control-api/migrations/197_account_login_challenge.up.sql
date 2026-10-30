LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_197$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 196 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 196 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=196 AND migration_id='196_platform_system_other_settings' AND checksum_sha256='296e9eb4404dc60f37b3564e960fa6194ad8ae7b0cd41925fc5c64c26feed011' AND down_checksum_sha256='8d2af779e2da3218c17f063de6fd6e99f60838994a16ee120dbcf9966a992eb7' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       to_regclass('account_login_challenge_writes_197') IS NOT NULL OR
       to_regclass('account_login_challenges_197') IS NOT NULL OR
       to_regclass('account_login_challenge_verify_receipts_197') IS NOT NULL OR
       to_regclass('account_login_challenge_dispatch_claims_197') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 197 requires the exact verified 196 release head' USING ERRCODE='P1970';
    END IF;
END;
$migration_197$;

INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at) VALUES
    ('account_login_verification',1,'email','登录验证码','请使用以下验证码完成登录：',ARRAY[]::text[],clock_timestamp()),
    ('account_login_verification',1,'sms','','您的登录验证码为：',ARRAY[]::text[],clock_timestamp());

CREATE TABLE account_login_challenge_writes_197 (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY(scope_id,idempotency_key)
);

CREATE TABLE account_login_challenges_197 (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    write_idempotency_key text NOT NULL,
    user_id uuid,
    channel text NOT NULL CHECK(channel IN ('email','sms')),
    destination_digest bytea NOT NULL CHECK(octet_length(destination_digest)=32),
    source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
    otp_digest bytea NOT NULL CHECK(octet_length(otp_digest)=32),
    failed_attempts integer NOT NULL CHECK(failed_attempts>=0),
    max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 10 AND failed_attempts<=max_attempts),
    issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at),
    state text NOT NULL CHECK(state IN ('queued','locked','consumed')),
    consumed_at timestamptz CHECK(consumed_at IS NULL OR isfinite(consumed_at)),
    FOREIGN KEY(scope_id,write_idempotency_key) REFERENCES account_login_challenge_writes_197(scope_id,idempotency_key) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(scope_id,write_idempotency_key),
    CHECK((state='consumed')=(consumed_at IS NOT NULL))
);

CREATE TABLE account_login_challenge_verify_receipts_197 (
    challenge_id uuid NOT NULL REFERENCES account_login_challenges_197(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    outcome text NOT NULL CHECK(outcome IN ('invalid','consumed')),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(challenge_id,idempotency_key)
);

CREATE TABLE account_login_challenge_dispatch_claims_197 (
    anonymous_dispatch_reference uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL REFERENCES account_login_challenges_197(id) ON DELETE RESTRICT,
    outbox_id uuid NOT NULL UNIQUE REFERENCES notification_outbox(id) ON DELETE RESTRICT,
    channel text NOT NULL CHECK(channel IN ('email','sms')),
    destination_digest bytea NOT NULL CHECK(octet_length(destination_digest)=32),
    key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
    sealed_payload bytea NOT NULL CHECK(octet_length(sealed_payload)>=17),
    aad_sha256 bytea NOT NULL CHECK(octet_length(aad_sha256)=32),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at) AND expires_at>created_at),
    UNIQUE(scope_id,challenge_id)
);

CREATE INDEX account_login_challenge_writes_source_created_197 ON account_login_challenge_writes_197(source_digest,created_at DESC);
CREATE INDEX account_login_challenge_writes_subject_created_197 ON account_login_challenge_writes_197(subject_digest,created_at DESC);
CREATE INDEX account_login_challenges_expiry_197 ON account_login_challenges_197(state,expires_at);

REVOKE ALL ON account_login_challenge_writes_197,account_login_challenges_197,account_login_challenge_verify_receipts_197,account_login_challenge_dispatch_claims_197 FROM PUBLIC;
