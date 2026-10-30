-- fix-l4usage (L4-USAGE-01, 029 占位，合入时主会话按 CH 头连号): a TCP
-- session in progress is billed by checkpoints, each the bytes since the
-- previous one, at checkpoint_at (a session crossing a month bills each
-- checkpoint in its own month). (node, listener, session, started, sequence)
-- is a checkpoint's identity: a redelivery replaces the same row. The
-- session's end fact names the bytes its checkpoints billed, so the end
-- bills only the rest. 1.0.35 is a fresh install: no backfill.
CREATE TABLE IF NOT EXISTS l4_usage_checkpoints_v1
(
    tenant_id UUID,
    node_id UUID,
    site_id UUID,
    stream_id UUID,
    package_subscription_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    listener_id UUID,
    session_id String,
    started_at DateTime64(3, 'UTC'),
    checkpoint_at DateTime64(3, 'UTC'),
    sequence UInt32,
    bytes_up UInt64,
    bytes_down UInt64,
    config_version_id UUID,
    config_revision UInt64,
    protocol LowCardinality(String),
    listen_port UInt16,
    event_id String,
    source_watermark UInt64
)
ENGINE = ReplacingMergeTree(source_watermark)
PARTITION BY toYYYYMM(checkpoint_at)
ORDER BY (tenant_id, node_id, listener_id, session_id, started_at, sequence)
TTL toDateTime(checkpoint_at, 'UTC') + INTERVAL 400 DAY DELETE;

ALTER TABLE l4_session_facts_v1
    ADD COLUMN IF NOT EXISTS checkpointed_bytes_up UInt64 DEFAULT 0 AFTER bytes_down;

ALTER TABLE l4_session_facts_v1
    ADD COLUMN IF NOT EXISTS checkpointed_bytes_down UInt64 DEFAULT 0 AFTER checkpointed_bytes_up;
