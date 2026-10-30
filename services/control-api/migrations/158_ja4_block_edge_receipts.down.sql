LOCK TABLE schema_migrations,firewall_command_outbox,ja4_block_edge_receipt_queue_158 IN ACCESS EXCLUSIVE MODE;

DO $migration_158$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>158 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>158 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=158 AND migration_id='158_ja4_block_edge_receipts' AND
              checksum_sha256='8d465893298a1641767ec0ec776660082c7e035c96eaa24eb90f14c136b792b4' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=157 AND migration_id='157_ja4_block_workflow' AND
              checksum_sha256='d6f9a03fcdc4cd47fe62fe861c8f57e3f25f11fe9bfa9abbb1db2732f411e104' AND
              down_checksum_sha256='0f31778af185f8505b528ba938fadb7655bbad43690c3a9790632b531ec6720c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 158 rollback requires the exact verified 158 head'
            USING ERRCODE='P1580';
    END IF;
    IF EXISTS(SELECT 1 FROM ja4_block_edge_receipt_queue_158) THEN
        RAISE EXCEPTION 'migration 158 rollback would discard JA4 edge receipt facts'
            USING ERRCODE='P1582';
    END IF;
END;
$migration_158$;

DROP TRIGGER ja4_block_edge_receipt_enqueue_158 ON firewall_command_outbox;
DROP TRIGGER ja4_block_edge_receipt_truncate_158 ON ja4_block_edge_receipt_queue_158;
DROP TRIGGER ja4_block_edge_receipt_guard_158 ON ja4_block_edge_receipt_queue_158;
DROP FUNCTION prevent_ja4_block_edge_receipt_truncate_158();
DROP FUNCTION guard_ja4_block_edge_receipt_158();
DROP FUNCTION enqueue_ja4_block_edge_receipt_158();
DROP TABLE ja4_block_edge_receipt_queue_158;
