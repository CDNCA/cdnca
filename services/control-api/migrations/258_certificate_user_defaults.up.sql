LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_258_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 257 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 257 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 257 AND migration_id = '257_waf_custom_rule_report_runtime_grants' AND
              checksum_sha256 = '99ca3814db70983028e2a368bd1f878934e69440399dfcdff35f6b19303804c7' AND
              down_checksum_sha256 = 'fed78c51a8c9f79755b4ac2f584d633a709cfc8901787954967ea704f64f150b' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 258 requires the exact verified 257 release head'
            USING ERRCODE = 'P2580';
    END IF;
END;
$migration_258_up$;

CREATE TABLE certificate_user_defaults (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    certificate_type text NOT NULL CHECK (certificate_type IN ('acme', 'uploaded')),
    dns_provider_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, user_id),
    FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, dns_provider_id) REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CHECK (certificate_type = 'acme' OR dns_provider_id IS NULL)
);

CREATE TABLE certificate_default_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation = 'certificate.defaults.update'),
    idempotency_key text NOT NULL CHECK (idempotency_key = btrim(idempotency_key) AND char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK ((completed_at IS NULL AND resource_id IS NULL AND response_status IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL))
);

CREATE INDEX certificate_default_write_requests_scope_created_idx
    ON certificate_default_write_requests(target_scope_id, created_at DESC);
