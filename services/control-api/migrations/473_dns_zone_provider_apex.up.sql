LOCK TABLE schema_migrations, dns_zones IN ACCESS EXCLUSIVE MODE;

DO $migration_473_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 472 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 472 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=472 AND
        migration_id='472_site_cache_status_header' AND
        checksum_sha256='bfa4893110282f6df2a541a7f15f92ec631db93e5ec27c8e246ef3e897a0a0e2' AND
        down_checksum_sha256='ff250fffa7d109a2cfa61a74c0141669fea2587c97c987bac387204879b8ea6f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='dns_zones' AND column_name='provider_zone_apex'
       ) THEN
        RAISE EXCEPTION 'migration 473 requires the exact verified 472 release head' USING ERRCODE='P4730';
    END IF;
END;
$migration_473_up$;

-- r136 retest-n1 (main session 10-24 00:15): a CNAME zone may be a subdomain
-- of the domain the DNS account hosts (cdn.868yun.com under 868yun.com).
-- provider_zone_apex is that hosted domain, found once from the provider's
-- domain list when the zone is saved (the longest hosted domain equal to the
-- zone name or a dot-suffix of it). Provider calls use the apex and record
-- names relative to it. NULL is a zone saved before 473: the first use looks
-- the apex up the same way and writes it back. Not part of the 089 claim
-- digests: filling it does not change which records a zone authorises.
ALTER TABLE dns_zones
    ADD COLUMN provider_zone_apex text CHECK (
        provider_zone_apex IS NULL OR (
            provider_zone_apex = lower(btrim(provider_zone_apex)) AND
            char_length(provider_zone_apex) BETWEEN 1 AND 253 AND
            (name = provider_zone_apex OR right(name, char_length(provider_zone_apex) + 1) = '.' || provider_zone_apex)
        )
    );
