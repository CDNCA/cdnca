-- P0070 remains fail-closed until a verified 007 release checksum is recorded.
SELECT throwIf(
    (SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = 'connections_ingest_receipts_v1') != 1,
    'migration 007 rollback requires the exact verified 007 head; receipt table is not present'
) FORMAT Null;

DROP TABLE IF EXISTS connections_ingest_receipts_v1 SYNC;
