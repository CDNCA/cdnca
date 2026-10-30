CREATE TABLE nodes (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1024),
    region text NOT NULL DEFAULT '' CHECK (char_length(region) <= 64),
    ipv4 inet CHECK (ipv4 IS NULL OR family(ipv4) = 4),
    ipv6 inet CHECK (ipv6 IS NULL OR family(ipv6) = 6),
    admin_state text NOT NULL DEFAULT 'pending'
        CHECK (admin_state IN ('pending', 'active', 'draining', 'disabled', 'retired')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX nodes_scope_name_lower_idx ON nodes (scope_id, lower(name));
CREATE INDEX nodes_scope_state_id_idx ON nodes (scope_id, admin_state, id);

CREATE TABLE node_enrollment_tokens (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    purpose text NOT NULL CHECK (purpose IN ('initial_enrollment', 're_enrollment')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    consume_request_id text CHECK (consume_request_id IS NULL OR char_length(consume_request_id) BETWEEN 1 AND 128),
    consume_request_digest bytea CHECK (
        consume_request_digest IS NULL OR octet_length(consume_request_digest) = 32
    ),
    CHECK (expires_at > created_at),
    CHECK (
        (consumed_at IS NULL AND consume_request_id IS NULL AND consume_request_digest IS NULL) OR
        (consumed_at IS NOT NULL AND consume_request_id IS NOT NULL AND consume_request_digest IS NOT NULL)
    ),
    UNIQUE (id, node_id, purpose)
);

CREATE INDEX node_enrollment_tokens_node_idx ON node_enrollment_tokens (node_id, created_at DESC);
CREATE INDEX node_enrollment_tokens_active_expiry_idx ON node_enrollment_tokens (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE node_enrollment_authorizations (
    id uuid PRIMARY KEY,
    token_id uuid NOT NULL UNIQUE,
    node_id uuid NOT NULL,
    purpose text NOT NULL,
    request_id text NOT NULL UNIQUE CHECK (char_length(request_id) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    authorized_at timestamptz NOT NULL,
    FOREIGN KEY (token_id, node_id, purpose)
        REFERENCES node_enrollment_tokens(id, node_id, purpose) ON DELETE RESTRICT
);

CREATE INDEX node_enrollment_authorizations_node_idx
    ON node_enrollment_authorizations (node_id, authorized_at DESC);

