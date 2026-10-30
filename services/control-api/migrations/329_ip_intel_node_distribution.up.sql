LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_329_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 328 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 328 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=328 AND
        migration_id='328_l4_session_log' AND
        checksum_sha256='88f45b5711dba3c53c8c1c0a0fdf75cde7f1fc036e3bdc4a38456854df9e9fb1' AND
        down_checksum_sha256='0a68e90db060befb2cc03aef8765a3bff4f95a8027352a4ee87b649eb7ec1589' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.ip_intel_node_distributions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 329 requires the exact verified 328 release head' USING ERRCODE='P3290';
    END IF;
END;
$migration_329_up$;

-- r136-g3b (placeholder number): node-side artifact deployments
-- (docs/architecture/ip-intel-artifact.md §10.3). A configuration holding the
-- ip-intel manifest / part media types delivers a node-wide artifact (the IP
-- intelligence library) and never becomes a node's running configuration.
-- Those media types live only in the platform scope, alone in their
-- configuration; edgestatus and node serving tell the deliveries apart by them.
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

-- One configuration per library revision (the manifest carries the license
-- envelope; a re-signed envelope of the same revision reuses it).
-- @ip-intel-node-distribution-ddl
CREATE TABLE ip_intel_node_distributions (
    config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT,
    revision bigint NOT NULL UNIQUE CHECK (revision BETWEEN 1 AND 9007199254740991),
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    compressed_bytes bigint NOT NULL CHECK (compressed_bytes > 0),
    created_at timestamptz NOT NULL
);

-- The newest revision each node has applied and was announced to system
-- republication (first readiness completes the scopes waiting on it).
CREATE TABLE ip_intel_node_ready_marks (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    marked_at timestamptz NOT NULL
);
-- @end-ip-intel-node-distribution-ddl

REVOKE ALL ON FUNCTION bind_node_artifact_media_type_329() FROM PUBLIC;
GRANT SELECT, INSERT ON ip_intel_node_distributions TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON ip_intel_node_ready_marks TO cdnca_control_app, cdnca_control_runtime;
