LOCK TABLE schema_migrations, acme_issuance_challenge_events IN ACCESS EXCLUSIVE MODE;

DO $migration_393_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 392 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 392 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=392 AND
        migration_id='392_package_monitor_audit_hash_v2' AND
        checksum_sha256='6ca9f2f0f63718778374cffaebfb7cc6e0e3f56e2383139c0e7b9d829d68ec20' AND
        down_checksum_sha256='fe1ce7fafa4c2434296783adc449e099bc60dac6486abccd3953a7a8712f60ca' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.validate_acme_challenge_publication_048()') IS NULL THEN
        RAISE EXCEPTION 'migration 393 requires the exact verified 392 release head' USING ERRCODE='P3930';
    END IF;
END;
$migration_393_up$;

-- 393（r136 testdebt4 占位：接在 392 之后；合入时主会话改号）。
-- The worker's DNS-01 zero-match cleanup (acmeworker cleanupChallenge: the
-- intent was persisted but recovery finds no remote TXT record) claims and
-- completes cleanup without a remote handle, a transition 047 allows
-- (intent -> cleanup_claimed). 048 required a handle on every non-intent
-- event, so such a challenge could never be cleaned and its operation stayed
-- stuck. Cleanup events may now carry no handle; once a handle was published
-- it stays immutable, so an empty cleanup only follows intent or an empty
-- cleanup claim.

CREATE OR REPLACE FUNCTION validate_acme_challenge_publication_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    attempt acme_issuance_challenge_attempts%ROWTYPE;
    previous acme_issuance_challenge_events%ROWTYPE;
    frozen_provider text;
    expected_digest bytea;
BEGIN
    SELECT * INTO attempt
    FROM acme_issuance_challenge_attempts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND attempt_id = NEW.attempt_id;
    SELECT request_snapshot ->> 'ProviderRef' INTO frozen_provider
    FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id;

    IF attempt.challenge_type = 'http-01' THEN
        IF NEW.provider_ref IS NOT NULL OR NEW.remote_record_ref IS NOT NULL
           OR NEW.exact_value_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'HTTP-01 challenge cannot carry DNS publication facts'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    expected_digest := sha256(convert_to(attempt.exact_value, 'UTF8'));
    IF NEW.exact_value_sha256 IS DISTINCT FROM expected_digest
       OR (NEW.state = 'intent' AND (
           NEW.provider_ref IS NOT NULL OR NEW.remote_record_ref IS NOT NULL
       ))
       OR (NEW.state <> 'intent' AND NOT (
           -- Zero-match cleanup: recovery found no remote TXT record, so the
           -- claim and its completion carry no handle. The immutability check
           -- below keeps this to a chain that never published one.
           NEW.state IN ('cleanup_claimed', 'cleaned')
           AND NEW.provider_ref IS NULL AND NEW.remote_record_ref IS NULL
       ) AND (
           NEW.provider_ref IS DISTINCT FROM frozen_provider OR NEW.remote_record_ref IS NULL
       )) THEN
        RAISE EXCEPTION 'DNS-01 publication fact is incomplete or mismatched'
            USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision > 1 THEN
        SELECT * INTO previous
        FROM acme_issuance_challenge_events
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND operation_id = NEW.operation_id
          AND attempt_id = NEW.attempt_id
          AND revision = NEW.revision - 1;
        IF NEW.exact_value_sha256 IS DISTINCT FROM previous.exact_value_sha256
           OR (previous.state <> 'intent' AND (
               NEW.provider_ref IS DISTINCT FROM previous.provider_ref
               OR NEW.remote_record_ref IS DISTINCT FROM previous.remote_record_ref
           )) THEN
            RAISE EXCEPTION 'DNS-01 remote record handle is immutable after publication'
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    IF NEW.remote_record_ref IS NOT NULL AND EXISTS (
        SELECT 1 FROM acme_issuance_challenge_events other
        WHERE other.tenant_scope_id = NEW.tenant_scope_id
          AND other.provider_ref = NEW.provider_ref
          AND other.remote_record_ref = NEW.remote_record_ref
          AND (other.operation_id, other.attempt_id)
              IS DISTINCT FROM (NEW.operation_id, NEW.attempt_id)
    ) THEN
        RAISE EXCEPTION 'DNS remote record handle is already bound to another challenge'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;
