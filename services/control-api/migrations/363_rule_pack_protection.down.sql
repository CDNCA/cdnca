LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_363_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 363 OR
       (SELECT max(version) FROM schema_migrations) <> 363 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=363 AND
        migration_id='363_rule_pack_protection' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 363 down requires the exact verified migration head' USING ERRCODE='P3639';
    END IF;
    -- Encrypted packs and catalog packs cannot be represented before 363.
    IF EXISTS (SELECT 1 FROM node_rule_pack_keys) OR EXISTS (SELECT 1 FROM rule_pack_artifacts WHERE sealed OR source = 'catalog') OR
       EXISTS (SELECT 1 FROM artifact_catalog_entries WHERE encryption = 'install_wrapped') OR
       EXISTS (SELECT 1 FROM rule_packs WHERE created_by_user_id IS NULL OR updated_by_user_id IS NULL) THEN
        RAISE EXCEPTION 'encrypted or catalog rule packs exist; rollback of 363 is unsafe' USING ERRCODE='P3631';
    END IF;
END;
$migration_363_down$;

DROP TABLE node_rule_pack_keys;
ALTER TABLE rule_pack_artifacts
    DROP CONSTRAINT rule_pack_artifacts_creator_363_ck,
    DROP CONSTRAINT rule_pack_artifacts_sealed_363_ck,
    DROP COLUMN wrapped_key,
    DROP COLUMN sealed,
    DROP CONSTRAINT rule_pack_artifacts_size_363_ck,
    ADD CONSTRAINT rule_pack_artifacts_size_bytes_check CHECK (size_bytes BETWEEN 1 AND 1048576),
    ALTER COLUMN created_by_user_id SET NOT NULL;
ALTER TABLE rule_packs ALTER COLUMN created_by_user_id SET NOT NULL, ALTER COLUMN updated_by_user_id SET NOT NULL;
ALTER TABLE local_artifacts DROP COLUMN current_wrapped_key;
ALTER TABLE artifact_catalog_entries DROP CONSTRAINT artifact_catalog_entries_wrapped_key_363_ck, DROP COLUMN wrapped_key;
