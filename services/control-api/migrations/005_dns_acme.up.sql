INSERT INTO permissions (name, description) VALUES
    ('dns.read', 'Read DNS providers, zones, and records in the active tenant scope'),
    ('dns.manage', 'Manage DNS providers, zones, and records in the active tenant scope'),
    ('certificates.read', 'Read certificate orders in the active tenant scope'),
    ('certificates.manage', 'Create and renew certificate orders in the active tenant scope');

CREATE TABLE dns_providers (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    provider_type text NOT NULL CHECK (
        provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun')
    ),
    credential_key_id text NOT NULL CHECK (credential_key_id <> ''),
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) > 28),
    credentials_configured boolean NOT NULL DEFAULT true CHECK (credentials_configured),
    status text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'disabled')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, name)
);

CREATE INDEX dns_providers_scope_created_idx
    ON dns_providers (scope_id, created_at DESC, id DESC);

CREATE TABLE dns_zones (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    provider_id uuid NOT NULL,
    name text NOT NULL CHECK (name = lower(btrim(name)) AND char_length(name) BETWEEN 1 AND 253),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'failed')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, name),
    FOREIGN KEY (scope_id, provider_id)
        REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX dns_zones_provider_created_idx
    ON dns_zones (provider_id, created_at DESC, id DESC);

CREATE TABLE dns_records (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    zone_id uuid NOT NULL,
    name text NOT NULL CHECK (name = lower(btrim(name)) AND char_length(name) BETWEEN 1 AND 253),
    record_type text NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'TXT')),
    content text NOT NULL CHECK (content <> '' AND char_length(content) <= 1024),
    ttl integer NOT NULL CHECK (ttl BETWEEN 60 AND 86400),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'failed')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, id),
    UNIQUE (zone_id, name, record_type, content),
    FOREIGN KEY (scope_id, zone_id)
        REFERENCES dns_zones(scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX dns_records_zone_created_idx
    ON dns_records (zone_id, created_at DESC, id DESC);

CREATE TABLE certificate_orders (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    dns_provider_id uuid,
    domains text[] NOT NULL CHECK (cardinality(domains) BETWEEN 1 AND 100),
    challenge_type text NOT NULL CHECK (challenge_type IN ('http-01', 'dns-01')),
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'validating', 'issuing', 'issued', 'deploying', 'active',
                   'renewal_due', 'failed', 'revoked')
    ),
    auto_renew boolean NOT NULL DEFAULT true,
    renewal_of_order_id uuid,
    not_after timestamptz,
    failure_code text,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, id),
    FOREIGN KEY (scope_id, dns_provider_id)
        REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, renewal_of_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    CHECK ((challenge_type = 'dns-01' AND dns_provider_id IS NOT NULL) OR challenge_type = 'http-01'),
    CHECK ((status IN ('issued', 'deploying', 'active', 'renewal_due', 'revoked') AND not_after IS NOT NULL)
        OR status IN ('pending', 'validating', 'issuing', 'failed')),
    CHECK ((status = 'failed' AND failure_code IS NOT NULL) OR (status <> 'failed' AND failure_code IS NULL))
);

CREATE UNIQUE INDEX certificate_orders_open_renewal_idx
    ON certificate_orders (renewal_of_order_id)
    WHERE renewal_of_order_id IS NOT NULL AND status NOT IN ('failed', 'revoked');
CREATE INDEX certificate_orders_scope_created_idx
    ON certificate_orders (scope_id, created_at DESC, id DESC);
CREATE INDEX certificate_orders_renewal_due_idx
    ON certificate_orders (not_after)
    WHERE auto_renew AND status = 'active';

CREATE TABLE dns_acme_outbox (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    aggregate_type text NOT NULL CHECK (aggregate_type IN ('certificate_order')),
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('certificate.order.requested')),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (aggregate_type, aggregate_id, event_type),
    FOREIGN KEY (scope_id, aggregate_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    CHECK ((status = 'completed' AND completed_at IS NOT NULL) OR (status <> 'completed' AND completed_at IS NULL))
);

CREATE INDEX dns_acme_outbox_pending_idx
    ON dns_acme_outbox (next_attempt_at, id) WHERE status IN ('pending', 'failed');

CREATE TABLE dns_acme_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation <> ''),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX dns_acme_write_requests_scope_created_idx
    ON dns_acme_write_requests (target_scope_id, created_at DESC);
