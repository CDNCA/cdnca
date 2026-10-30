CREATE TABLE site_batch_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX site_batch_write_requests_scope_created_idx
    ON site_batch_write_requests (actor_scope_id, created_at DESC);
