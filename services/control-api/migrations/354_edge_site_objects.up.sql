LOCK TABLE schema_migrations, config_versions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_node_artifacts_333 IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE edge_publication_compile_inputs IN ACCESS EXCLUSIVE MODE;

DO $migration_354_up$
DECLARE
    snapshot_constraint text;
    compile_constraint text;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 353 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 353 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=353 AND
        migration_id='353_artifact_sync' AND
        checksum_sha256='25291860ab06be9a3dc35d7b54d0333d017be463a710f8040dd2ad860f28538e' AND
        down_checksum_sha256='a01337f726ef3b0c570cf220d1de45e907c85f381a3061262f47c8e7cc184d05' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('edge_site_objects') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 354 requires the exact verified 353 release head' USING ERRCODE='P3540';
    END IF;
    SELECT conname INTO snapshot_constraint FROM pg_constraint
    WHERE conrelid='config_versions'::regclass AND contype='c' AND
          pg_get_constraintdef(oid) LIKE '%canonical_snapshot)%4194304%';
    IF snapshot_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 354 requires the 4 MiB canonical snapshot bound' USING ERRCODE='P3541';
    END IF;
    EXECUTE format('ALTER TABLE config_versions DROP CONSTRAINT %I', snapshot_constraint);
    SELECT conname INTO compile_constraint FROM pg_constraint
    WHERE conrelid='edge_publication_compile_inputs'::regclass AND contype='c' AND
          pg_get_constraintdef(oid) LIKE '%site_runtime_v2)::text)%4194304%';
    IF compile_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 354 requires the 4 MiB v2 compile input bound' USING ERRCODE='P3545';
    END IF;
    EXECUTE format('ALTER TABLE edge_publication_compile_inputs DROP CONSTRAINT %I', compile_constraint);
END;
$migration_354_up$;

-- Site runtime v8 (ADR 0009 §8.3, libs/edgeconfig/siteobject): the canonical
-- snapshot is still the whole v2 document (cross-scope composition, IPv6
-- rollout, challenge targets and CRS republication read it).
ALTER TABLE config_versions ADD CONSTRAINT config_versions_canonical_snapshot_354
    CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 268435456);
-- A v2 publication's compile inputs hold its runtime document; nodes accept
-- documents up to 16 MiB (agent siteruntimev2 maxDocumentBytes).
ALTER TABLE edge_publication_compile_inputs ADD CONSTRAINT edge_publication_compile_inputs_v2_size_354
    CHECK (site_runtime_v2 IS NULL OR
        jsonb_typeof(site_runtime_v2) = 'object' AND octet_length(site_runtime_v2::text) <= 16777216);

-- One content key per configuration scope and epoch. Every site object of the
-- scope is sealed once with a key derived from it and the object's digest;
-- nodes get it in their HPKE key artifact. It is as confidential as the
-- canonical snapshot (which holds the same plaintext). 1.0.35 uses epoch 1.
CREATE TABLE edge_site_object_keys (
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    key_epoch bigint NOT NULL CHECK (key_epoch BETWEEN 1 AND 9007199254740991),
    content_key bytea NOT NULL CHECK (octet_length(content_key) = 32),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (configuration_scope_id, key_epoch)
);

-- Sealed objects, addressed by plaintext SHA-256 within a scope and epoch;
-- an unchanged object is stored once however many publications reference it.
CREATE TABLE edge_site_objects (
    configuration_scope_id uuid NOT NULL,
    key_epoch bigint NOT NULL,
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    kind text NOT NULL CHECK (kind IN ('scope', 'bucket', 'site', 'file')),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 8388624),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (configuration_scope_id, key_epoch, sha256),
    FOREIGN KEY (configuration_scope_id, key_epoch)
        REFERENCES edge_site_object_keys(configuration_scope_id, key_epoch) ON DELETE RESTRICT
);

-- The publication a config version's root names. member_sha256 is the
-- ascending concatenation of the 32-byte digests the root references (scope,
-- buckets, sites, files): a node may fetch exactly these.
CREATE TABLE edge_site_object_publications (
    config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT,
    configuration_scope_id uuid NOT NULL,
    key_epoch bigint NOT NULL,
    root_sha256 bytea NOT NULL CHECK (octet_length(root_sha256) = 32),
    member_sha256 bytea NOT NULL CHECK (
        octet_length(member_sha256) BETWEEN 64 AND 268435456 AND octet_length(member_sha256) % 32 = 0),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (configuration_scope_id, key_epoch)
        REFERENCES edge_site_object_keys(configuration_scope_id, key_epoch) ON DELETE RESTRICT
);

CREATE FUNCTION protect_edge_site_objects_354() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'edge site objects are immutable' USING ERRCODE='P3542';
END;
$$;

CREATE TRIGGER edge_site_object_keys_immutable BEFORE UPDATE OR DELETE ON edge_site_object_keys
    FOR EACH ROW EXECUTE FUNCTION protect_edge_site_objects_354();
CREATE TRIGGER edge_site_objects_immutable BEFORE UPDATE OR DELETE ON edge_site_objects
    FOR EACH ROW EXECUTE FUNCTION protect_edge_site_objects_354();
CREATE TRIGGER edge_site_object_publications_immutable BEFORE UPDATE OR DELETE ON edge_site_object_publications
    FOR EACH ROW EXECUTE FUNCTION protect_edge_site_objects_354();
CREATE TRIGGER edge_site_object_keys_no_truncate BEFORE TRUNCATE ON edge_site_object_keys
    FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_site_objects_354();
CREATE TRIGGER edge_site_objects_no_truncate BEFORE TRUNCATE ON edge_site_objects
    FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_site_objects_354();
CREATE TRIGGER edge_site_object_publications_no_truncate BEFORE TRUNCATE ON edge_site_object_publications
    FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_site_objects_354();

-- A v8 security activation candidate's node row names the node's HPKE key
-- envelope (artifact_id) and the digest the node reports running: the shared
-- signed root's (artifact_sha256).
CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM configuration_artifacts artifact
        JOIN config_versions version ON version.id=artifact.config_version_id
        WHERE artifact.id=NEW.artifact_id AND artifact.config_version_id=NEW.config_version_id
          AND version.configuration_scope_id=NEW.tenant_scope_id
          AND artifact.kind='configuration'
          AND artifact.encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'
          AND artifact.recipient_key_id=NEW.recipient_key_id
          AND artifact.sha256=sha256(artifact.wire_bytes) AND (
            (artifact.media_type<>'application/vnd.cdnca.edge-site-object-key+json;version=1' AND
             artifact.sha256=NEW.artifact_sha256) OR
            (artifact.media_type='application/vnd.cdnca.edge-site-object-key+json;version=1' AND EXISTS (
                SELECT 1 FROM configuration_artifacts root
                WHERE root.config_version_id=NEW.config_version_id AND root.kind='configuration'
                  AND root.encryption_algorithm='none'
                  AND root.media_type='application/vnd.cdnca.edge-site-root+json;version=1'
                  AND root.sha256=NEW.artifact_sha256 AND root.sha256=sha256(root.wire_bytes))))
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON edge_site_object_keys, edge_site_objects, edge_site_object_publications FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_edge_site_objects_354() FROM PUBLIC;
GRANT SELECT, INSERT ON edge_site_object_keys, edge_site_objects, edge_site_object_publications
    TO cdnca_control_app, cdnca_control_runtime;
