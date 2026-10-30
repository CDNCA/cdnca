LOCK TABLE schema_migrations, configuration_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_358_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 358 OR
       (SELECT max(version) FROM schema_migrations) <> 358 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=358 AND
        migration_id='358_node_artifact_sets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 358 down requires the exact verified migration head' USING ERRCODE='P3581';
    END IF;
    -- Deployments already delivered node artifact sets; their configuration
    -- rows are immutable history and cannot be explained without 358.
    IF EXISTS (SELECT 1 FROM node_artifact_sets) OR EXISTS (SELECT 1 FROM node_artifact_segments) THEN
        RAISE EXCEPTION 'migration 358 down refuses to orphan node artifact set deployments' USING ERRCODE='P3581';
    END IF;
END;
$migration_358_down$;

DROP TABLE node_artifact_applied_items;
DROP TABLE node_artifact_set_receipts;
DROP TABLE node_artifact_sets;
DROP TABLE node_artifact_segments;
DROP TRIGGER configuration_artifacts_node_artifact_358 ON configuration_artifacts;
DROP FUNCTION bind_node_artifact_media_type_358();

-- Restore 329 exactly.
CREATE FUNCTION bind_node_artifact_media_type_329() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    platform boolean;
    node_artifact boolean;
BEGIN
    SELECT scope.kind='platform' INTO platform FROM config_versions version
        JOIN access_scopes scope ON scope.id=version.configuration_scope_id WHERE version.id=NEW.config_version_id;
    node_artifact := NEW.media_type IN ('application/vnd.cdnca.ip-intel-node-manifest+json;version=1',
        'application/vnd.cdnca.ip-intel-node-part;version=1');
    IF node_artifact AND (NOT COALESCE(platform,false) OR NEW.kind <> 'configuration' OR
       NEW.encryption_algorithm <> 'none' OR EXISTS (SELECT 1 FROM configuration_artifacts other
           WHERE other.config_version_id=NEW.config_version_id AND other.media_type NOT IN
           ('application/vnd.cdnca.ip-intel-node-manifest+json;version=1',
            'application/vnd.cdnca.ip-intel-node-part;version=1'))) OR
       (NOT node_artifact AND EXISTS (SELECT 1 FROM configuration_artifacts other
           WHERE other.config_version_id=NEW.config_version_id AND other.media_type IN
           ('application/vnd.cdnca.ip-intel-node-manifest+json;version=1',
            'application/vnd.cdnca.ip-intel-node-part;version=1'))) THEN
        RAISE EXCEPTION 'node-side artifacts belong to the platform scope only'
            USING ERRCODE='23514', CONSTRAINT='configuration_artifacts_node_artifact_329';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER configuration_artifacts_node_artifact_329 BEFORE INSERT ON configuration_artifacts
    FOR EACH ROW EXECUTE FUNCTION bind_node_artifact_media_type_329();

CREATE TABLE ip_intel_node_distributions (
    config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT,
    revision bigint NOT NULL UNIQUE CHECK (revision BETWEEN 1 AND 9007199254740991),
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    compressed_bytes bigint NOT NULL CHECK (compressed_bytes > 0),
    created_at timestamptz NOT NULL
);

CREATE TABLE ip_intel_node_ready_marks (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    marked_at timestamptz NOT NULL
);

REVOKE ALL ON FUNCTION bind_node_artifact_media_type_329() FROM PUBLIC;
GRANT SELECT, INSERT ON ip_intel_node_distributions TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON ip_intel_node_ready_marks TO cdnca_control_app, cdnca_control_runtime;
