LOCK TABLE schema_migrations, acme_issuance_challenge_events IN ACCESS EXCLUSIVE MODE;

DO $migration_393_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 393 OR
       (SELECT max(version) FROM schema_migrations) <> 393 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=393 AND
        migration_id='393_acme_zero_match_cleanup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 393 down requires the exact verified migration head' USING ERRCODE='P3931';
    END IF;
    IF EXISTS (
        SELECT 1 FROM acme_issuance_challenge_events event
        JOIN acme_issuance_challenge_attempts attempt
          ON attempt.tenant_scope_id = event.tenant_scope_id
         AND attempt.operation_id = event.operation_id
         AND attempt.attempt_id = event.attempt_id
        WHERE attempt.challenge_type = 'dns-01'
          AND event.state IN ('cleanup_claimed', 'cleaned')
          AND event.remote_record_ref IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 393 down would strand zero-match DNS-01 cleanup facts'
            USING ERRCODE='P3932';
    END IF;
END;
$migration_393_down$;

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
       OR (NEW.state <> 'intent' AND (
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
