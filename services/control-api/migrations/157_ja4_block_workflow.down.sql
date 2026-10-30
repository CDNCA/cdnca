LOCK TABLE schema_migrations,ja4_block_receipts_157,ja4_block_outbox_157,ja4_block_workflows_157 IN ACCESS EXCLUSIVE MODE;

DO $migration_157$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>157 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>157 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=157 AND migration_id='157_ja4_block_workflow' AND
              checksum_sha256='d6f9a03fcdc4cd47fe62fe861c8f57e3f25f11fe9bfa9abbb1db2732f411e104' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=156 AND migration_id='156_runtime_patch_policy' AND
              checksum_sha256='34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788' AND
              down_checksum_sha256='a29ada54fad54860ca7da7f200bd99cd95132e91e4015d5ebfaf5835f215d495' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 157 rollback requires the exact verified 157 head'
            USING ERRCODE='P1570';
    END IF;
    IF EXISTS(SELECT 1 FROM ja4_block_receipts_157) OR
       EXISTS(SELECT 1 FROM ja4_block_outbox_157) OR
       EXISTS(SELECT 1 FROM ja4_block_workflows_157) THEN
        RAISE EXCEPTION 'migration 157 rollback would discard JA4 block workflow facts'
            USING ERRCODE='P1572';
    END IF;
END;
$migration_157$;

DROP TRIGGER ja4_block_receipt_truncate_157 ON ja4_block_receipts_157;
DROP TRIGGER ja4_block_outbox_truncate_157 ON ja4_block_outbox_157;
DROP TRIGGER ja4_block_workflow_truncate_157 ON ja4_block_workflows_157;
DROP TRIGGER ja4_block_receipt_guard_157 ON ja4_block_receipts_157;
DROP TRIGGER ja4_block_workflow_guard_157 ON ja4_block_workflows_157;
DROP FUNCTION prevent_ja4_block_truncate_157();
DROP FUNCTION guard_ja4_block_receipt_157();
DROP FUNCTION guard_ja4_block_workflow_157();
DROP TABLE ja4_block_receipts_157;
DROP TABLE ja4_block_outbox_157;
DROP TABLE ja4_block_workflows_157;
