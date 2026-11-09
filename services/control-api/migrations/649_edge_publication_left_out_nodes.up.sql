-- 649（发布记录存下被跳过与不支持按节点屏蔽的节点；前驱 648_node_key_envelope_oversized_audit_index）：edge_config_publications 加两列，默认空数组，不回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_649_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 648 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 648 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=648 AND
        migration_id='648_node_key_envelope_oversized_audit_index' AND
        checksum_sha256='22eb08464ed15def5f716c39823334c08556f253b4a980df9754195074709a33' AND
        down_checksum_sha256='96929b92dc5eb86ae76b638e68165c142559d4d4c4e19859d1325caa609eb7f9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='edge_config_publications'
          AND column_name IN ('key_envelope_oversized_node_ids', 'site_selection_unsupported_node_ids')
       ) THEN
        RAISE EXCEPTION 'migration 649 requires the exact verified 648 release head' USING ERRCODE='P6490';
    END IF;
END;
$migration_649_up$;

-- The nodes a publication did not reach as intended, kept
-- on the publication so the publication list and detail show them for every
-- channel (manual, automatic, system republication, sold package, system
-- configuration): key_envelope_oversized_node_ids were left out of the
-- release (their Agent predates SITE_SELECTION and the key envelope exceeds
-- the 4096 bytes it takes; their old configuration stays in effect),
-- site_selection_unsupported_node_ids got it but serve every website of the
-- scope. Only the round that published counts. Earlier publications keep the
-- empty default (no backfill; the publication audit has the facts).
-- A constant default adds the columns without rewriting the table.
ALTER TABLE edge_config_publications
    ADD COLUMN key_envelope_oversized_node_ids uuid[] NOT NULL DEFAULT '{}'
        CONSTRAINT edge_config_publications_key_envelope_oversized_649_check CHECK (
            cardinality(key_envelope_oversized_node_ids) <= 10000 AND
            array_position(key_envelope_oversized_node_ids, NULL) IS NULL),
    ADD COLUMN site_selection_unsupported_node_ids uuid[] NOT NULL DEFAULT '{}'
        CONSTRAINT edge_config_publications_site_selection_unsupported_649_check CHECK (
            cardinality(site_selection_unsupported_node_ids) <= 10000 AND
            array_position(site_selection_unsupported_node_ids, NULL) IS NULL);
