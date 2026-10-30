-- P0060: this migration is valid only after the exact 006 access-event-state
-- authority has been verified. The control-plane migrator records this digest
-- before applying the first DDL; a missing or mismatched predecessor is fatal.
-- predecessor_up_sha256=ad7191e2f4895f489bb3534c314460e01f60c66c7ae7e38abf9cf70bef39f721
-- predecessor_down_sha256=6c08c80b18c9d753175efb5453735b4bd926eca74fb27ab64498a590ec36914a

CREATE TABLE IF NOT EXISTS connections_ingest_receipts_v1
(
    schema_version UInt32,
    receipt_id String,
    batch_id String,
    event_id String,
    tenant_id UUID,
    installation_id String,
    site_id UUID,
    package_subscription_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    connections UInt64,
    payload_sha256 FixedString(64),
    canonical_event_sha256 FixedString(64),
    evidence_sha256 FixedString(64),
    source_watermark UInt64,
    finalized_through DateTime64(3, 'UTC'),
    nats_stream LowCardinality(String),
    nats_durable LowCardinality(String),
    nats_stream_sequence UInt64,
    nats_consumer_sequence UInt64,
    puback_stream LowCardinality(String),
    puback_sequence UInt64,
    puback_duplicate UInt8,
    clickhouse_insert_token FixedString(64),
    state LowCardinality(String),
    state_rank UInt8,
    received_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    CONSTRAINT connections_schema_version_v1 CHECK schema_version = 1,
    CONSTRAINT connections_identity_v1 CHECK length(receipt_id) > 0 AND length(receipt_id) <= 256
        AND length(batch_id) > 0 AND length(batch_id) <= 256 AND length(event_id) > 0 AND length(event_id) <= 256,
    CONSTRAINT connections_scope_v1 CHECK tenant_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND site_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND package_subscription_id != toUUID('00000000-0000-0000-0000-000000000000'),
    CONSTRAINT connections_value_v1 CHECK connections > 0 AND source_watermark > 0 AND finalized_through >= occurred_at,
    CONSTRAINT connections_digest_v1 CHECK length(payload_sha256) = 64 AND length(canonical_event_sha256) = 64
        AND length(evidence_sha256) = 64 AND length(clickhouse_insert_token) = 64,
    CONSTRAINT connections_sequence_v1 CHECK length(nats_stream) > 0 AND length(nats_durable) > 0
        AND nats_stream_sequence > 0 AND nats_consumer_sequence > 0
        AND length(puback_stream) > 0 AND puback_sequence > 0,
    CONSTRAINT connections_state_v1 CHECK
        (state = 'received' AND state_rank = 1) OR
        (state = 'ch_prepared' AND state_rank = 2) OR
        (state = 'broker_ack_observed' AND state_rank = 3)
)
ENGINE = ReplacingMergeTree(state_rank)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id, receipt_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;
