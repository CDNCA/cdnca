-- Roll back only the P013 columns and constraint; receipt rows remain append-only.
ALTER TABLE connections_ingest_receipts_v1
    DROP CONSTRAINT IF EXISTS finalized_connection_dimensions_v1;

ALTER TABLE connections_ingest_receipts_v1
    DROP COLUMN IF EXISTS listen_port,
    DROP COLUMN IF EXISTS domain,
    DROP COLUMN IF EXISTS node_id;

