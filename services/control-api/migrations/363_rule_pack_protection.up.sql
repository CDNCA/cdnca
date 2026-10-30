LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_363_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 362 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 362 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=362 AND
        migration_id='362_aggregated_edge_import' AND
        checksum_sha256='25f0e327bf06645a658a6bb06ef880fa579bf619b08a376208106334002af3cd' AND
        down_checksum_sha256='c4aa6d3607c8f0d7fc85ec3f4650b48e40e053c0bdf50425dccef9100419db6c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.node_rule_pack_keys') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 363 requires the exact verified 362 release head' USING ERRCODE='P3630';
    END IF;
END;
$migration_363_up$;

-- r136 PA-14 (placeholder number 363, guard on the 362 head; renumbered on merge): rule pack content
-- protection (docs/adr/0007-plugin-platform-architecture.md §6). The control
-- plane keeps encrypted packs sealed (cdnca.rule-pack-sealed/v1: public
-- manifest + AES-256-GCM ciphertext) and never decrypts them; it only
-- unwraps the content key in memory to wrap it again for each node.
--   * artifact_catalog_entries / local_artifacts: the installation-wrapped
--     content key of an install_wrapped entry (delivered / downloaded).
--   * rule_pack_artifacts: catalog packs (no creating user), sealed bytes
--     (up to 2 MiB) and their installation-wrapped key.
--   * node_rule_pack_keys: the content key wrapped to one node's artifact
--     encryption key for one sealed object (input of the node artifact set).
ALTER TABLE artifact_catalog_entries
    ADD COLUMN wrapped_key text NOT NULL DEFAULT '' CHECK (wrapped_key = '' OR (wrapped_key ~ '^[A-Za-z0-9_-]+$' AND char_length(wrapped_key) BETWEEN 16 AND 684)),
    ADD CONSTRAINT artifact_catalog_entries_wrapped_key_363_ck CHECK ((encryption = 'install_wrapped') = (wrapped_key <> ''));

ALTER TABLE local_artifacts
    ADD COLUMN current_wrapped_key text NOT NULL DEFAULT ''
        CHECK (current_wrapped_key = '' OR (current_wrapped_key ~ '^[A-Za-z0-9_-]+$' AND char_length(current_wrapped_key) BETWEEN 16 AND 684));

ALTER TABLE rule_packs ALTER COLUMN created_by_user_id DROP NOT NULL, ALTER COLUMN updated_by_user_id DROP NOT NULL;
ALTER TABLE rule_pack_artifacts
    ALTER COLUMN created_by_user_id DROP NOT NULL,
    DROP CONSTRAINT rule_pack_artifacts_size_bytes_check,
    ADD CONSTRAINT rule_pack_artifacts_size_363_ck CHECK (size_bytes BETWEEN 1 AND 2097152),
    ADD COLUMN sealed boolean NOT NULL DEFAULT false,
    ADD COLUMN wrapped_key text NOT NULL DEFAULT '' CHECK (wrapped_key = '' OR (wrapped_key ~ '^[A-Za-z0-9_-]+$' AND char_length(wrapped_key) BETWEEN 16 AND 684)),
    ADD CONSTRAINT rule_pack_artifacts_sealed_363_ck CHECK (sealed = (wrapped_key <> '') AND (NOT sealed OR source = 'catalog')),
    ADD CONSTRAINT rule_pack_artifacts_creator_363_ck CHECK ((source = 'catalog') = (created_by_user_id IS NULL));

CREATE TABLE node_rule_pack_keys (
    node_id uuid NOT NULL,
    recipient_key_id text NOT NULL CHECK (recipient_key_id ~ '^x25519:[0-9a-f]{64}$'),
    sealed_sha256 text NOT NULL CHECK (sealed_sha256 ~ '^[0-9a-f]{64}$'),
    pack_id text NOT NULL CHECK (char_length(pack_id) BETWEEN 8 AND 160),
    version text NOT NULL CHECK (char_length(version) BETWEEN 5 AND 64),
    wrapped_key text NOT NULL CHECK (wrapped_key ~ '^[A-Za-z0-9_-]+$' AND char_length(wrapped_key) BETWEEN 16 AND 684),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, recipient_key_id, sealed_sha256),
    FOREIGN KEY (recipient_key_id, node_id) REFERENCES node_artifact_encryption_keys(id, node_id) ON DELETE CASCADE,
    FOREIGN KEY (sealed_sha256) REFERENCES rule_pack_artifacts(sha256) ON DELETE CASCADE
);
CREATE INDEX node_rule_pack_keys_sealed_363 ON node_rule_pack_keys (sealed_sha256);

GRANT SELECT, INSERT, DELETE ON node_rule_pack_keys TO cdnca_control_app;
GRANT SELECT ON node_rule_pack_keys TO cdnca_control_runtime;
