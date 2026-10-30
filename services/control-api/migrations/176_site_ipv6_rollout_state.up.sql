LOCK TABLE schema_migrations,config_versions,sites IN ACCESS EXCLUSIVE MODE;

DO $migration_176$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>175 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>175 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=175 AND migration_id='175_identity_verification_issuer_authority' AND
              checksum_sha256='55dd21f5024894066f3bc20ff100229027e0051e3f33fadf64503c28b9305448' AND
              down_checksum_sha256='7158ccd1514407955e479b71ca3c59015294bfae705e5250c0c00d5d8d541799' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('site_ipv6_rollout_targets') IS NOT NULL OR
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='sites' AND
              column_name IN ('ipv6_enabled','ipv6_runtime_state','ipv6_runtime_source_revision')) THEN
        RAISE EXCEPTION 'migration 176 requires the exact verified 175 release head and an untouched IPv6 site schema'
            USING ERRCODE='P1760';
    END IF;
END;
$migration_176$;

ALTER TABLE config_versions
    ADD CONSTRAINT config_versions_id_scope_unique_176 UNIQUE(id,configuration_scope_id);

ALTER TABLE sites
    ADD COLUMN ipv6_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN ipv6_runtime_state text NOT NULL DEFAULT 'active'
        CHECK(ipv6_runtime_state IN ('disabled','pending','active','failed')),
    ADD COLUMN ipv6_runtime_source_revision bigint NOT NULL DEFAULT 0
        CHECK(ipv6_runtime_source_revision>=0);

CREATE TABLE site_ipv6_rollout_targets (
    config_version_id uuid NOT NULL,
    configuration_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK(source_revision>0),
    desired_enabled boolean NOT NULL,
    site_revision bigint NOT NULL CHECK(site_revision>0),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(config_version_id,site_id),
    FOREIGN KEY(config_version_id,configuration_scope_id)
        REFERENCES config_versions(id,configuration_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(configuration_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT
);

CREATE INDEX site_ipv6_rollout_targets_site_idx
    ON site_ipv6_rollout_targets(configuration_scope_id,site_id,source_revision DESC);

CREATE FUNCTION prevent_site_ipv6_rollout_target_mutation_176()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'site IPv6 rollout targets are append-only' USING ERRCODE='P1761';
END;
$$;

CREATE TRIGGER site_ipv6_rollout_targets_immutable_176
BEFORE UPDATE OR DELETE ON site_ipv6_rollout_targets
FOR EACH ROW EXECUTE FUNCTION prevent_site_ipv6_rollout_target_mutation_176();

CREATE TRIGGER site_ipv6_rollout_targets_no_truncate_176
BEFORE TRUNCATE ON site_ipv6_rollout_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_ipv6_rollout_target_mutation_176();

WITH source_versions AS (
    SELECT version.id,version.configuration_scope_id,version.created_at,
           convert_from(version.canonical_snapshot,'UTF8')::jsonb AS document
    FROM config_versions version
), source_sites AS (
    SELECT version.id AS config_version_id,version.configuration_scope_id,version.created_at,
           version.document->>'schema' AS schema_name,
           version.document->>'source_revision' AS source_revision_text,
           site.value AS site_document
    FROM source_versions version
    CROSS JOIN LATERAL jsonb_array_elements(version.document->'sites') site(value)
    WHERE version.document->>'schema' IN ('cdnca.edge.config-source/v1','cdnca.edge.site-runtime/v2')
)
INSERT INTO site_ipv6_rollout_targets(
    config_version_id,configuration_scope_id,site_id,source_revision,desired_enabled,site_revision,created_at
)
SELECT source.config_version_id,source.configuration_scope_id,
       (source.site_document->>'id')::uuid,
       (source.source_revision_text)::bigint,
       CASE WHEN source.schema_name='cdnca.edge.site-runtime/v2' THEN
            NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(source.site_document->'listeners') listener(value)
                WHERE listener.value->>'address_family'='ipv4'
            )
            ELSE CASE WHEN source.site_document ? 'ipv6_enabled' AND
                           source.site_document->>'ipv6_enabled' IN ('true','false')
                      THEN (source.site_document->>'ipv6_enabled')::boolean ELSE true END
       END,
       (source.site_document->>'revision')::bigint,
       source.created_at
FROM source_sites source
WHERE source.site_document->>'id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  AND (source.site_document->>'revision') ~ '^[1-9][0-9]*$'
  AND source.source_revision_text ~ '^[1-9][0-9]*$'
ON CONFLICT(config_version_id,site_id) DO NOTHING;

REVOKE ALL ON site_ipv6_rollout_targets FROM PUBLIC;
