-- Additive v2 observations retain v1 positive/subscription semantics.
ALTER TABLE connections_ingest_receipts_v1
    ADD COLUMN IF NOT EXISTS config_version_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000');
ALTER TABLE connections_ingest_receipts_v1
    DROP CONSTRAINT IF EXISTS connections_schema_version_v1,
    DROP CONSTRAINT IF EXISTS connections_scope_v1,
    DROP CONSTRAINT IF EXISTS connections_value_v1;
ALTER TABLE connections_ingest_receipts_v1
    ADD CONSTRAINT connections_schema_version_v2 CHECK schema_version IN (1,2),
    ADD CONSTRAINT connections_scope_v2 CHECK tenant_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND site_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND ((schema_version=1 AND package_subscription_id != toUUID('00000000-0000-0000-0000-000000000000'))
          OR (schema_version=2 AND config_version_id != toUUID('00000000-0000-0000-0000-000000000000'))),
    ADD CONSTRAINT connections_value_v2 CHECK source_watermark>0 AND finalized_through>=occurred_at
        AND (schema_version=2 OR connections>0);
