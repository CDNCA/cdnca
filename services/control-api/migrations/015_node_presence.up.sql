CREATE TABLE node_presence (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('online', 'offline')),
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    heartbeat_sequence bigint NOT NULL CHECK (heartbeat_sequence > 0),
    event_id uuid NOT NULL,
    request_id uuid NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    occurred_at timestamptz NOT NULL,
    projected_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    confirmed_session_epoch bigint CHECK (confirmed_session_epoch > 0),
    confirmed_heartbeat_sequence bigint CHECK (confirmed_heartbeat_sequence > 0),
    confirmed_event_id uuid,
    confirmed_request_id uuid,
    confirmed_payload_digest bytea CHECK (
        confirmed_payload_digest IS NULL OR octet_length(confirmed_payload_digest) = 32
    ),
    online_since timestamptz,
    offline_since timestamptz,
    current_config_version_id uuid,
    previous_config_version_id uuid,
    loaded_config_version_id uuid,
    openresty_state text NOT NULL
        CHECK (openresty_state IN ('running', 'degraded', 'stopped', 'failed')),
    firewall_state text NOT NULL
        CHECK (firewall_state IN ('running', 'degraded', 'stopped', 'failed')),
    filesystem_total_bytes numeric(20, 0) NOT NULL CHECK (filesystem_total_bytes >= 0),
    filesystem_available_bytes numeric(20, 0) NOT NULL CHECK (filesystem_available_bytes >= 0),
    cache_used_bytes numeric(20, 0) NOT NULL CHECK (cache_used_bytes >= 0),
    active_deployments jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(active_deployments) = 'array'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    CHECK (filesystem_available_bytes <= filesystem_total_bytes),
    CHECK (
        (confirmed_session_epoch IS NULL AND confirmed_heartbeat_sequence IS NULL AND
         confirmed_event_id IS NULL AND confirmed_request_id IS NULL AND
         confirmed_payload_digest IS NULL AND last_seen_at IS NULL) OR
        (confirmed_session_epoch IS NOT NULL AND confirmed_heartbeat_sequence IS NOT NULL AND
         confirmed_event_id IS NOT NULL AND confirmed_request_id IS NOT NULL AND
         confirmed_payload_digest IS NOT NULL AND last_seen_at IS NOT NULL)
    ),
    CHECK (
        (status = 'online' AND online_since IS NOT NULL AND offline_since IS NULL AND
         confirmed_session_epoch IS NOT NULL) OR
        (status = 'offline' AND offline_since IS NOT NULL)
    )
);

CREATE INDEX node_presence_online_last_seen_idx
    ON node_presence (last_seen_at, node_id)
    WHERE status = 'online';

CREATE INDEX node_presence_status_node_idx
    ON node_presence (status, node_id);
