LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_199_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 199 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 199 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=199 AND migration_id='199_platform_system_settings_runtime_grants' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=198 AND migration_id='198_notification_anonymous_verification_events' AND checksum_sha256='77b26643f95e5fcebe1d5382a24f8ba5ea615b512e07ad9cc64165c6c4e1d4e9' AND down_checksum_sha256='f0976671a2930579cacc2ae2296c0df52bfaa128b2ee0864ca8f2a0bfc294677' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 199 rollback requires the exact verified release heads' USING ERRCODE='P1990';
    END IF;
END;
$migration_199_down$;

DO $revoke_runtime$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        REVOKE SELECT,INSERT,UPDATE ON
            platform_system_settings, platform_system_settings_write_requests,
            platform_system_cleanup_settings, platform_system_cleanup_settings_write_requests,
            platform_system_user_settings, platform_system_user_settings_write_requests,
            platform_system_mail_settings, platform_system_mail_settings_write_requests,
            platform_system_other_settings, platform_system_other_settings_write_requests
            FROM cdnca_control_app;
    END IF;
END;
$revoke_runtime$;
