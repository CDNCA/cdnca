LOCK TABLE schema_migrations,account_registration_verification_intents_159,
    account_registration_terms_159,account_registration_requests_159,users IN ACCESS EXCLUSIVE MODE;

DO $migration_159$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>159 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>159 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=159 AND migration_id='159_account_registration' AND
              checksum_sha256='8a4d250bff304aed957f58390cab80818b0c22a6be24e08113a53c764d35d787' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=158 AND migration_id='158_ja4_block_edge_receipts' AND
              checksum_sha256='8d465893298a1641767ec0ec776660082c7e035c96eaa24eb90f14c136b792b4' AND
              down_checksum_sha256='dace062a3bcc560a8ed8a7ac9e4718ff59acdb9b71ebd8fc84c9d270b3210b0a' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 159 rollback requires the exact verified 159 head'
            USING ERRCODE='P1590';
    END IF;
    IF EXISTS(SELECT 1 FROM account_registration_verification_intents_159) OR
       EXISTS(SELECT 1 FROM account_registration_terms_159) OR
       EXISTS(SELECT 1 FROM account_registration_requests_159) OR EXISTS(
        SELECT 1 FROM audit_events WHERE action='identity.account_registration.accept'
    ) THEN
        RAISE EXCEPTION 'migration 159 rollback would discard account registration facts'
            USING ERRCODE='P1593';
    END IF;
END;
$migration_159$;

DROP TRIGGER account_registration_verification_truncate_159 ON account_registration_verification_intents_159;
DROP TRIGGER account_registration_terms_truncate_159 ON account_registration_terms_159;
DROP TRIGGER account_registration_request_truncate_159 ON account_registration_requests_159;
DROP TRIGGER account_registration_verification_guard_159 ON account_registration_verification_intents_159;
DROP TRIGGER account_registration_terms_guard_159 ON account_registration_terms_159;
DROP TRIGGER account_registration_request_guard_159 ON account_registration_requests_159;
DROP FUNCTION prevent_account_registration_truncate_159();
DROP FUNCTION guard_account_registration_fact_159();
DROP FUNCTION guard_account_registration_request_159();
DROP TABLE account_registration_verification_intents_159;
DROP TABLE account_registration_terms_159;
DROP TABLE account_registration_requests_159;
DROP INDEX users_phone_registration_unique_159;
DROP INDEX users_email_registration_unique_159;
