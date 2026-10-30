LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_283_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 282 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 282 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=282 AND
        migration_id='282_security_rule_catalog_consumer' AND
        checksum_sha256='6809951208c23bd51918e881e6c355231403a88ccfb2bf9f4f9b5e61faf4c99b' AND
        down_checksum_sha256='60e6b9c785c603df1df0cd2d95584e1697d15c3a62f16335ac0d9a1016ca00c6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_custom_rule_report_state') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 283 requires the exact verified 282 release head' USING ERRCODE='P2830';
    END IF;
END;
$migration_283_up$;

-- Sender state of the forced cdnca.security-custom-rule-report/v2 upload
-- (tenant CC rule groups / matchers / filters and WAF policies). One row per
-- installation; a changed report digest consumes the next sequence. There is
-- deliberately no enable/disable switch.
CREATE TABLE security_custom_rule_report_state (
    installation_id uuid PRIMARY KEY,
    sequence bigint NOT NULL CHECK (sequence > 0),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128),
    observed_at timestamptz NOT NULL,
    report jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    report_digest bytea NOT NULL CHECK (octet_length(report_digest) = 32),
    sent_at timestamptz,
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 200),
    updated_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON security_custom_rule_report_state TO cdnca_control_app, cdnca_control_runtime;
