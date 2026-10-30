LOCK TABLE schema_migrations, security_policies, security_policy_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_344_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 343 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 343 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=343 AND
        migration_id='343_challenge_policy_redelivery' AND
        checksum_sha256='718012174b2f86e4e56d01da55b111ff6a44f153c9e3d35bcd765c82996602ef' AND
        down_checksum_sha256='d2bccbb4a57b9079a58d2fba8d77c734245268998d42d1af0e46bab37a0ede31' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='security_policies' AND column_name='quick_block'
       ) THEN
        RAISE EXCEPTION 'migration 344 requires the exact verified 343 release head' USING ERRCODE='P3440';
    END IF;
END;
$migration_344_up$;

-- r136 G3-d #13 (placeholder number; renumbered on merge): a WAF policy's
-- quick block switches (block CN / global IDC, chosen carriers; allowed
-- crawlers) — securitypolicy.QuickBlock. The policy's rules carry the
-- system-managed rules it expands to, so every compiler sees ordinary
-- rules; only PUT /v1/security-policies/{id}/quick-block changes them.
-- NULL means never configured. The policy version documents carry the same
-- object.
ALTER TABLE security_policies
    ADD COLUMN quick_block jsonb,
    ADD CONSTRAINT security_policies_quick_block_344
        CHECK (quick_block IS NULL OR kind = 'waf' AND jsonb_typeof(quick_block) = 'object');

ALTER TABLE security_policy_write_requests
    DROP CONSTRAINT security_policy_write_requests_operation_check,
    ADD CONSTRAINT security_policy_write_requests_operation_check CHECK (operation IN (
        'security_policy.create', 'security_policy.update', 'security_policy.delete',
        'security_policy.quick_block'
    ));
