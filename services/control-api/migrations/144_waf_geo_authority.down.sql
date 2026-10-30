LOCK TABLE schema_migrations, waf_geo_site_heads, waf_geo_catalog_revisions,
    waf_geo_publications, waf_geo_binding_transitions IN ACCESS EXCLUSIVE MODE;

DO $migration_144$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 144 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 144 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 144 AND migration_id = '144_waf_geo_authority' AND
              checksum_sha256 = '7fac4e1bdec793d461ef3a1735c81d4b7c020dd876fa565dd919a68bb493ce95' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 143 AND migration_id = '143_cache_policy_definitions' AND
              checksum_sha256 = 'bbe9d4210c9cd5d58a831e210a5a57586723824d25c1deb70cabcdf5efbd8147' AND
              down_checksum_sha256 = '872a9e22a27b3c866dec3b00df65594da978229584abbb7cd9732e6444819283' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 144 rollback requires the exact verified 144 head'
            USING ERRCODE = 'P1440';
    END IF;
    IF EXISTS (SELECT 1 FROM waf_geo_site_heads) OR
       EXISTS (SELECT 1 FROM waf_geo_catalog_revisions) OR
       EXISTS (SELECT 1 FROM waf_geo_publications) OR
       EXISTS (SELECT 1 FROM waf_geo_binding_transitions) THEN
        RAISE EXCEPTION 'migration 144 rollback would discard WAF geo authority facts'
            USING ERRCODE = 'P1447';
    END IF;
END;
$migration_144$;

DROP TRIGGER waf_geo_binding_transitions_no_truncate_144 ON waf_geo_binding_transitions;
DROP TRIGGER waf_geo_publications_no_truncate_144 ON waf_geo_publications;
DROP TRIGGER waf_geo_catalog_revisions_no_truncate_144 ON waf_geo_catalog_revisions;
DROP TRIGGER waf_geo_site_heads_no_truncate_144 ON waf_geo_site_heads;
DROP FUNCTION prevent_waf_geo_truncate_144();
DROP TRIGGER waf_geo_site_heads_transition_144 ON waf_geo_site_heads;
DROP FUNCTION validate_waf_geo_head_transition_144();
DROP TRIGGER waf_geo_binding_transitions_append_only_144 ON waf_geo_binding_transitions;
DROP FUNCTION protect_waf_geo_transition_144();
DROP TRIGGER waf_geo_publications_append_only_144 ON waf_geo_publications;
DROP FUNCTION protect_waf_geo_publication_144();
DROP TRIGGER waf_geo_catalog_revisions_append_only_144 ON waf_geo_catalog_revisions;
DROP FUNCTION protect_waf_geo_revision_144();

DROP TABLE waf_geo_binding_transitions;
DROP TABLE waf_geo_publications;
ALTER TABLE waf_geo_site_heads
    DROP CONSTRAINT waf_geo_site_heads_lkg_144_fk,
    DROP CONSTRAINT waf_geo_site_heads_active_144_fk,
    DROP CONSTRAINT waf_geo_site_heads_latest_144_fk;
DROP TABLE waf_geo_catalog_revisions;
DROP TABLE waf_geo_site_heads;
DROP FUNCTION valid_waf_geo_trusted_crawlers_144(jsonb);
