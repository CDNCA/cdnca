LOCK TABLE schema_migrations, dns_providers, dns_provider_credential_history IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 106 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 106 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=106 AND migration_id='106_dns_provider_credential_lifecycle'
          AND checksum_sha256='097ca7d3fcdf878ff11cc891e8a8b05abe3dfd923b9153fdc15ee616d3415adf'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=105 AND migration_id='105_upgrade_canary_active_probe_lkg'
          AND checksum_sha256='aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b'
          AND down_checksum_sha256='f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 106 rollback requires the verified 106 head' USING ERRCODE='P1061';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dns_provider_credential_history WHERE credential_event <> 'baseline'
    ) THEN
        RAISE EXCEPTION 'migration 106 rollback would discard credential lifecycle history' USING ERRCODE='P1062';
    END IF;
END;
$$;

DELETE FROM dns_provider_credential_history WHERE credential_event='baseline';
DROP TRIGGER dns_provider_credential_history_update_106 ON dns_providers;
DROP TRIGGER dns_provider_credential_history_insert_106 ON dns_providers;
DROP TRIGGER dns_provider_credential_lifecycle_106 ON dns_providers;
DROP FUNCTION dns_provider_credential_history_106();
DROP FUNCTION dns_provider_credential_lifecycle_106();
DROP TABLE dns_provider_credential_history;
ALTER TABLE dns_providers
    DROP COLUMN credential_revoked,
    DROP COLUMN credential_version;
