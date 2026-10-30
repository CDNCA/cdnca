-- P013 binds finalized connection dimensions to the frozen 012 query-projection head.
-- predecessor_up_sha256=a6f21060eff79d6a0346041b64bec90bc31cff551f922be23f81b829218c9e0e
-- predecessor_down_sha256=c23e9762cd933cde906b4fc93aa632d40a034c94c03081db8379123f23e91c09

ALTER TABLE connections_ingest_receipts_v1
    ADD COLUMN IF NOT EXISTS node_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER tenant_id,
    ADD COLUMN IF NOT EXISTS domain LowCardinality(String) DEFAULT '' AFTER node_id,
    ADD COLUMN IF NOT EXISTS listen_port UInt16 DEFAULT 0 AFTER domain;

ALTER TABLE connections_ingest_receipts_v1
    ADD CONSTRAINT IF NOT EXISTS finalized_connection_dimensions_v1 CHECK
        node_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND length(domain) > 0
        AND listen_port BETWEEN 1 AND 65535;

