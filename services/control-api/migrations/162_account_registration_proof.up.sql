LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_162$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>161 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>161 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=161 AND migration_id='161_recharge_identity_eligibility' AND
              checksum_sha256='67edc7f614f05c0bd69551ae43d9b52bdd7e0a4b1c16c655adb76aa0a5bba4d6' AND
              down_checksum_sha256='8043517489d8adffe1023313c89730c459284252c647c4ba838c3b897087236d' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('account_registration_proofs_162') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 162 requires a contiguous verified 161 release head'
            USING ERRCODE='P1620';
    END IF;
END;
$migration_162$;

CREATE TABLE account_registration_proofs_162 (
    evidence_id uuid PRIMARY KEY,
    reference_digest bytea NOT NULL,
    channel text NOT NULL CHECK(channel IN ('email','sms')),
    destination_digest bytea NOT NULL CHECK(octet_length(destination_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
    risk_context text NOT NULL CHECK(risk_context IN ('normal','step_up')),
    human_verified_at timestamptz NOT NULL CHECK(isfinite(human_verified_at)),
    contact_verified_at timestamptz NOT NULL CHECK(isfinite(contact_verified_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
    attempt_revision bigint NOT NULL CHECK(attempt_revision>0),
    use_revision bigint NOT NULL DEFAULT 0 CHECK(use_revision IN (0,1)),
    consumed_idempotency_digest bytea,
    consumed_binding_digest bytea,
    consumed_at timestamptz CHECK(consumed_at IS NULL OR isfinite(consumed_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    UNIQUE (reference_digest),
    CHECK(octet_length(reference_digest)=32),
    CHECK(human_verified_at<=expires_at AND contact_verified_at<=expires_at),
    CHECK(
        (use_revision=0 AND consumed_idempotency_digest IS NULL AND
         consumed_binding_digest IS NULL AND consumed_at IS NULL) OR
        (use_revision=1 AND octet_length(consumed_idempotency_digest)=32 AND
         octet_length(consumed_binding_digest)=32 AND consumed_at IS NOT NULL)
    )
);

REVOKE ALL ON account_registration_proofs_162 FROM PUBLIC;
