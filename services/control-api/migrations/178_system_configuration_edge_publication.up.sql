LOCK TABLE schema_migrations,system_configuration_revisions,edge_config_publications,
           config_versions,rollouts IN ACCESS EXCLUSIVE MODE;

DO $migration_178$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>177 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>177 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=177 AND migration_id='177_site_ingress_source_origin' AND
              checksum_sha256='2c30c0ae8ac61027f16ad024e562b350ff3737d684fc1115491acfd65c0da58c' AND
              down_checksum_sha256='8354642bf48d51b26ef722b6f7d79798313398795ad2adc19b208b6db71455e9' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.system_configuration_edge_publications') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 178 requires the exact verified 177 release head and an untouched system configuration publication schema'
            USING ERRCODE='P1780';
    END IF;
END;
$migration_178$;

CREATE TABLE system_configuration_edge_publications (
    platform_scope_id uuid NOT NULL,
    system_revision bigint NOT NULL CHECK (system_revision > 0),
    system_snapshot_sha256 bytea NOT NULL CHECK (octet_length(system_snapshot_sha256)=32),
    tenant_scope_id uuid NOT NULL REFERENCES edge_configuration_scopes(scope_id) ON DELETE RESTRICT,
    tenant_source_revision bigint NOT NULL CHECK (tenant_source_revision > 0),
    publication_id uuid NOT NULL REFERENCES edge_config_publications(id) ON DELETE RESTRICT,
    config_version_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256)=32),
    reason_code text NOT NULL CHECK (reason_code='system_configuration_activated'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (platform_scope_id,system_revision,tenant_scope_id),
    UNIQUE (tenant_scope_id,publication_id),
    UNIQUE (tenant_scope_id,config_version_id),
    UNIQUE (tenant_scope_id,rollout_id),
    FOREIGN KEY (platform_scope_id,system_revision)
        REFERENCES system_configuration_revisions(platform_scope_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,config_version_id)
        REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,rollout_id)
        REFERENCES rollouts(configuration_scope_id,id) ON DELETE RESTRICT,
    CHECK (created_at>=timestamptz '0001-01-01 00:00:00+00' AND
           created_at<timestamptz '10000-01-01 00:00:00+00')
);

CREATE INDEX system_configuration_edge_publications_revision_idx
    ON system_configuration_edge_publications(platform_scope_id,system_revision,tenant_scope_id);

CREATE FUNCTION validate_system_configuration_edge_publication_178()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM system_configuration_revisions revision
        WHERE revision.platform_scope_id=NEW.platform_scope_id AND revision.revision=NEW.system_revision
          AND revision.status IN ('validated','active')
          AND revision.snapshot_sha256=NEW.system_snapshot_sha256
    ) OR NOT EXISTS (
        SELECT 1 FROM access_scopes platform
        WHERE platform.id=NEW.platform_scope_id AND platform.kind='platform' AND platform.tenant_id IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM access_scopes tenant
        WHERE tenant.id=NEW.tenant_scope_id AND tenant.kind='tenant' AND tenant.tenant_id IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM edge_config_publications publication
        WHERE publication.id=NEW.publication_id AND publication.configuration_scope_id=NEW.tenant_scope_id
          AND publication.source_revision=NEW.tenant_source_revision
          AND publication.config_version_id=NEW.config_version_id
          AND publication.rollout_id=NEW.rollout_id
          AND publication.artifact_sha256=NEW.artifact_sha256
    ) THEN
        RAISE EXCEPTION 'invalid system configuration edge publication binding' USING ERRCODE='P1783';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_edge_publications_validate
BEFORE INSERT ON system_configuration_edge_publications
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_edge_publication_178();

CREATE FUNCTION prevent_system_configuration_edge_publication_mutation_178()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'system configuration edge publications are append-only' USING ERRCODE='P1784';
END;
$$;

CREATE TRIGGER system_configuration_edge_publications_append_only
BEFORE UPDATE OR DELETE ON system_configuration_edge_publications
FOR EACH ROW EXECUTE FUNCTION prevent_system_configuration_edge_publication_mutation_178();

CREATE FUNCTION prevent_system_configuration_edge_publication_truncate_178()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'system configuration edge publications cannot be truncated' USING ERRCODE='P1785';
END;
$$;

CREATE TRIGGER system_configuration_edge_publications_no_truncate
BEFORE TRUNCATE ON system_configuration_edge_publications
FOR EACH STATEMENT EXECUTE FUNCTION prevent_system_configuration_edge_publication_truncate_178();
