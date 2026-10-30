LOCK TABLE schema_migrations, configuration_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_358_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 357 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 357 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=357 AND
        migration_id='357_recharge_payment_legacy_reconcile_drop' AND
        checksum_sha256='5e8101deee14f96bb09769b33831facd4215a539df5ec169040f761ca2d97cb7' AND
        down_checksum_sha256='8dbecc582284d023d24e3aee071497db192c4bfcc8c6ae6f612af9d94b5131c1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_artifact_sets') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 358 requires the exact verified 357 release head' USING ERRCODE='P3580';
    END IF;
END;
$migration_358_up$;

-- r136 PA-01 (placeholder number; renumbered on merge): node artifact sets
-- (libs/edgeconfig/artifactset, ADR 0007 section 4.3) replace the
-- ip-intel-only node delivery of 329. Node-side artifact deployments are now
-- segment objects (one platform-scope configuration per segment digest,
-- shared by every node) and per-node sets (one configuration per node and
-- revision holding only the signed set). Both media types live only in the
-- platform scope, alone in their configuration, as plaintext configuration
-- artifacts. The 329 ip-intel media types are no longer node-side artifacts.
DROP TRIGGER configuration_artifacts_node_artifact_329 ON configuration_artifacts;
DROP FUNCTION bind_node_artifact_media_type_329();
-- 329's distribution tables had no producer in any release (ipinteldist was
-- never wired); the artifact set tables below replace them.
DROP TABLE ip_intel_node_ready_marks;
DROP TABLE ip_intel_node_distributions;

CREATE FUNCTION bind_node_artifact_media_type_358() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    platform boolean;
    node_artifact boolean;
BEGIN
    SELECT scope.kind='platform' INTO platform FROM config_versions version
        JOIN access_scopes scope ON scope.id=version.configuration_scope_id WHERE version.id=NEW.config_version_id;
    node_artifact := NEW.media_type IN ('application/vnd.cdnca.edge.artifact-set+json;version=1',
        'application/vnd.cdnca.edge.artifact-segment;version=1');
    IF node_artifact AND (NOT COALESCE(platform,false) OR NEW.kind <> 'configuration' OR
       NEW.encryption_algorithm <> 'none' OR NEW.compression <> 'none' OR EXISTS (
           SELECT 1 FROM configuration_artifacts other WHERE other.config_version_id=NEW.config_version_id)) OR
       (NOT node_artifact AND EXISTS (SELECT 1 FROM configuration_artifacts other
           WHERE other.config_version_id=NEW.config_version_id AND other.media_type IN
           ('application/vnd.cdnca.edge.artifact-set+json;version=1',
            'application/vnd.cdnca.edge.artifact-segment;version=1'))) THEN
        RAISE EXCEPTION 'node-side artifacts belong to the platform scope only, one per configuration'
            USING ERRCODE='23514', CONSTRAINT='configuration_artifacts_node_artifact_358';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER configuration_artifacts_node_artifact_358 BEFORE INSERT ON configuration_artifacts
    FOR EACH ROW EXECUTE FUNCTION bind_node_artifact_media_type_358();

-- @node-artifact-set-ddl
-- One shared configuration per segment object (content addressed).
CREATE TABLE node_artifact_segments (
    sha256 text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    config_version_id uuid NOT NULL UNIQUE REFERENCES config_versions(id) ON DELETE RESTRICT,
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 4194304),
    created_at timestamptz NOT NULL
);

-- Every set issued to a node; revision is monotonic per node.
CREATE TABLE node_artifact_sets (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    set_sha256 text NOT NULL CHECK (set_sha256 ~ '^[0-9a-f]{64}$'),
    items_sha256 text NOT NULL CHECK (items_sha256 ~ '^[0-9a-f]{64}$'),
    config_version_id uuid NOT NULL UNIQUE REFERENCES config_versions(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, revision)
);

-- The latest receipt of each node (cdnca.edge.artifact-set-receipt/v1).
CREATE TABLE node_artifact_set_receipts (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    set_sha256 text NOT NULL CHECK (set_sha256 ~ '^[0-9a-f]{64}$'),
    result text NOT NULL CHECK (result IN ('applied', 'rejected', 'pending')),
    active_revision bigint NOT NULL CHECK (active_revision >= 0),
    receipt jsonb NOT NULL,
    deployment_id uuid NOT NULL,
    reported_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CHECK (result <> 'applied' OR active_revision = revision),
    CHECK (result = 'applied' OR active_revision <> revision)
);

-- The items of each node's applied (active) set: what the publication gate
-- reads. announced_at marks that system republication was requested after
-- the item became applied (cleared by deleting the row when the item goes).
CREATE TABLE node_artifact_applied_items (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    artifact_id text NOT NULL CHECK (char_length(artifact_id) BETWEEN 1 AND 128),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
    item_revision bigint NOT NULL CHECK (item_revision BETWEEN 1 AND 9007199254740991),
    media_type text NOT NULL CHECK (char_length(media_type) BETWEEN 1 AND 128),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    set_revision bigint NOT NULL CHECK (set_revision > 0),
    applied_at timestamptz NOT NULL,
    announced_at timestamptz,
    PRIMARY KEY (node_id, artifact_id)
);
CREATE INDEX node_artifact_applied_items_media_358_idx ON node_artifact_applied_items(media_type, node_id);
-- @end-node-artifact-set-ddl

REVOKE ALL ON FUNCTION bind_node_artifact_media_type_358() FROM PUBLIC;
GRANT SELECT, INSERT ON node_artifact_segments, node_artifact_sets TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON node_artifact_set_receipts TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_artifact_applied_items TO cdnca_control_app, cdnca_control_runtime;
