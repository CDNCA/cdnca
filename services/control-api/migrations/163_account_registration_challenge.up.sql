LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_163$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>162 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>162 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=162 AND migration_id='162_account_registration_proof' AND
              checksum_sha256='41cae1972e4772c40b983b40def090b06e2abd741fc2265a894a9c91b097acde' AND
              down_checksum_sha256='581d71f285f6e2fbbcc60e4bbad675618def5eaadb5f2ac63e0b8898c0c8e830' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('account_registration_challenge_writes_163') IS NOT NULL OR
         to_regclass('account_registration_challenges_163') IS NOT NULL OR
         to_regclass('account_registration_challenge_verify_receipts_163') IS NOT NULL OR
         to_regclass('account_registration_challenge_dispatch_claims_163') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 163 requires a contiguous verified 162 release head'
            USING ERRCODE='P1630';
    END IF;
END;
$migration_163$;

CREATE TABLE account_registration_challenge_writes_163 (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    human_token_digest bytea NOT NULL CHECK(octet_length(human_token_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
    state text NOT NULL CHECK(state IN ('human_verifying','human_verified','human_rejected','human_unknown','queued')),
    human_verified_at timestamptz CHECK(human_verified_at IS NULL OR isfinite(human_verified_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY(scope_id,idempotency_key),
    UNIQUE (human_token_digest),
    CHECK((state IN ('human_verified','queued'))=(human_verified_at IS NOT NULL))
);

CREATE TABLE account_registration_challenges_163 (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    write_idempotency_key text NOT NULL,
    channel text NOT NULL CHECK(channel IN ('email','sms')),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    destination_digest bytea NOT NULL CHECK(octet_length(destination_digest)=32),
    source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
    otp_digest bytea NOT NULL CHECK(octet_length(otp_digest)=32),
    attempt_revision bigint NOT NULL CHECK(attempt_revision>0),
    failed_attempts integer NOT NULL CHECK(failed_attempts>=0),
    max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 10 AND failed_attempts<=max_attempts),
    human_verified_at timestamptz NOT NULL CHECK(isfinite(human_verified_at)),
    contact_verified_at timestamptz CHECK(contact_verified_at IS NULL OR isfinite(contact_verified_at)),
    issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at),
    state text NOT NULL CHECK(state IN ('queued','verified')),
    proof_evidence_id uuid,
    proof_key_id text,
    proof_nonce bytea,
    sealed_proof_reference bytea,
    proof_expires_at timestamptz CHECK(proof_expires_at IS NULL OR isfinite(proof_expires_at)),
    UNIQUE(scope_id,write_idempotency_key),
    FOREIGN KEY(scope_id,write_idempotency_key)
        REFERENCES account_registration_challenge_writes_163(scope_id,idempotency_key) ON DELETE RESTRICT,
    CHECK(
        (state='queued' AND contact_verified_at IS NULL AND proof_evidence_id IS NULL AND proof_key_id IS NULL AND
         proof_nonce IS NULL AND sealed_proof_reference IS NULL AND proof_expires_at IS NULL) OR
        (state='verified' AND contact_verified_at IS NOT NULL AND proof_evidence_id IS NOT NULL AND
         proof_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND octet_length(proof_nonce)=12 AND
         octet_length(sealed_proof_reference)>=17 AND proof_expires_at IS NOT NULL AND
         proof_expires_at>contact_verified_at)
    )
);

CREATE TABLE account_registration_challenge_verify_receipts_163 (
    challenge_id uuid NOT NULL REFERENCES account_registration_challenges_163(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    outcome text NOT NULL CHECK(outcome IN ('invalid','rate_limited','verified')),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(challenge_id,idempotency_key)
);

CREATE TABLE account_registration_challenge_dispatch_claims_163 (
    anonymous_dispatch_reference uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL REFERENCES account_registration_challenges_163(id) ON DELETE RESTRICT,
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

REVOKE ALL ON account_registration_challenge_writes_163 FROM PUBLIC;
REVOKE ALL ON account_registration_challenges_163 FROM PUBLIC;
REVOKE ALL ON account_registration_challenge_verify_receipts_163 FROM PUBLIC;
REVOKE ALL ON account_registration_challenge_dispatch_claims_163 FROM PUBLIC;
