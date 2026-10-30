LOCK TABLE schema_migrations,identity_verification_provider_sessions_v1,identity_verification_provider_attempts_v1,
    identity_verification_provider_uploads_v1,identity_verification_provider_callbacks_v1,
    identity_verification_provider_settlements_v1,identity_verification_erase_requests_v1,
    identity_verification_erase_receipts_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_169$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>169 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>169 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=169 AND migration_id='169_identity_verification_provider_sessions' AND
              checksum_sha256='e881ea03620506c0773bc8e22fa6fe93aff9b3bd5fae60feca8fafa0c0df254a' AND integrity_state='verified' AND
              metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=168 AND migration_id='168_recharge_payment_cancellation' AND
              checksum_sha256='afbcb3861d04a9d76933ca497789000dbcfec30cf5bfa2a3f1640775b303ecba' AND
              down_checksum_sha256='ff328c94456cbbc35006a08c10e671a0196a628e40a4bdc0ec8232703d41dac0' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 169 rollback requires the exact verified 169 head' USING ERRCODE='P1690';
    END IF;
    IF EXISTS(SELECT 1 FROM identity_verification_provider_sessions_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_provider_attempts_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_provider_uploads_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_provider_callbacks_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_provider_settlements_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_erase_requests_v1) OR
       EXISTS(SELECT 1 FROM identity_verification_erase_receipts_v1) THEN
        RAISE EXCEPTION 'migration 169 rollback would discard identity verification provider facts' USING ERRCODE='P1696';
    END IF;
END;
$migration_169$;

DROP FUNCTION enqueue_identity_verification_erase_requests_169(integer);

DROP TRIGGER identity_verification_erase_receipts_truncate_169 ON identity_verification_erase_receipts_v1;
DROP TRIGGER identity_verification_erase_requests_truncate_169 ON identity_verification_erase_requests_v1;
DROP TRIGGER identity_verification_provider_settlements_truncate_169 ON identity_verification_provider_settlements_v1;
DROP TRIGGER identity_verification_provider_callbacks_truncate_169 ON identity_verification_provider_callbacks_v1;
DROP TRIGGER identity_verification_provider_uploads_truncate_169 ON identity_verification_provider_uploads_v1;
DROP TRIGGER identity_verification_provider_attempts_truncate_169 ON identity_verification_provider_attempts_v1;
DROP TRIGGER identity_verification_provider_sessions_truncate_169 ON identity_verification_provider_sessions_v1;
DROP TRIGGER identity_verification_erase_receipts_append_only_169 ON identity_verification_erase_receipts_v1;
DROP TRIGGER identity_verification_provider_settlements_append_only_169 ON identity_verification_provider_settlements_v1;
DROP TRIGGER identity_verification_provider_callbacks_append_only_169 ON identity_verification_provider_callbacks_v1;
DROP TRIGGER identity_verification_provider_attempts_append_only_169 ON identity_verification_provider_attempts_v1;
DROP TRIGGER identity_verification_erase_requests_guard_169 ON identity_verification_erase_requests_v1;
DROP TRIGGER identity_verification_provider_uploads_guard_169 ON identity_verification_provider_uploads_v1;
DROP TRIGGER identity_verification_provider_sessions_guard_169 ON identity_verification_provider_sessions_v1;

DROP TABLE identity_verification_erase_receipts_v1;
DROP TABLE identity_verification_erase_requests_v1;
DROP TABLE identity_verification_provider_settlements_v1;
DROP TABLE identity_verification_provider_callbacks_v1;
DROP TABLE identity_verification_provider_uploads_v1;
DROP TABLE identity_verification_provider_attempts_v1;
DROP TABLE identity_verification_provider_sessions_v1;

DROP FUNCTION prevent_identity_verification_provider_truncate_169();
DROP FUNCTION prevent_identity_verification_provider_fact_mutation_169();
DROP FUNCTION guard_identity_verification_erase_request_169();
DROP FUNCTION guard_identity_verification_provider_upload_169();
DROP FUNCTION guard_identity_verification_provider_session_169();
