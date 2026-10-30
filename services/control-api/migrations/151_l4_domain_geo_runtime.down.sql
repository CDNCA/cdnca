LOCK TABLE schema_migrations, sites, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_151$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 151 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 151 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 151 AND migration_id = '151_l4_domain_geo_runtime' AND
              checksum_sha256 = '81a2cdcf12d5ddeb456b219c402043fe0b17b79f379da8436b79e3a7a3627668' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 150 AND migration_id = '150_node_metrics' AND
              checksum_sha256 = 'bfa06ab9348dd9791060bd7624747234507d8dca015934070e0bdf6f04b89a65' AND
              down_checksum_sha256 = 'c9702eddf7dbe49c1404da9acdcf4a8e26ce72adf599cb898dde355fd5903d22' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 151 rollback requires the exact verified 151 head'
            USING ERRCODE = 'P1510';
    END IF;
    IF EXISTS (
        SELECT 1 FROM l4_forwards
        WHERE site_id IS NOT NULL OR upstream_host IS NOT NULL OR remark <> '' OR proxy_protocol_inbound OR
              dns_policy <> '{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false}'::jsonb OR
              geo_policy <> '{"enabled":false,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]}'::jsonb
    ) OR EXISTS (
        SELECT 1 FROM l4_publish_intents
        WHERE site_id IS NOT NULL OR runtime_spec ->> 'schema_version' IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 151 rollback would discard L4 domain, geo, or site scope facts'
            USING ERRCODE = 'P1511';
    END IF;
END;
$migration_151$;

ALTER TABLE l4_publish_intents
    DROP CONSTRAINT l4_publish_intents_runtime_spec_151,
    DROP CONSTRAINT l4_publish_intents_site_schema_151,
    DROP CONSTRAINT l4_publish_intents_stream_scope_site_151,
    DROP COLUMN site_id,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_092
        CHECK (validate_l4_runtime_spec_092(stream_id, runtime_spec));

DROP FUNCTION validate_l4_runtime_spec_151(uuid, uuid, uuid, jsonb);

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_runtime_facts_151,
    DROP CONSTRAINT l4_forwards_endpoint_151,
    DROP CONSTRAINT l4_forwards_id_scope_site_151,
    DROP CONSTRAINT l4_forwards_site_scope_151,
    DROP COLUMN proxy_protocol_inbound,
    DROP COLUMN geo_policy,
    DROP COLUMN dns_policy,
    DROP COLUMN upstream_host,
    ALTER COLUMN upstream_address SET NOT NULL,
    DROP COLUMN remark,
    DROP COLUMN site_id;
