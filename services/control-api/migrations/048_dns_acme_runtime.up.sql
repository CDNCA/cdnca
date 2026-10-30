DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM acme_issuance_operations)
       OR EXISTS (SELECT 1 FROM acme_issuance_operation_events)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_attempts)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_events) THEN
        RAISE EXCEPTION 'cannot bind pre-existing ACME worker facts to certificate orders'
            USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (
        SELECT 1 FROM certificate_orders
        WHERE status IN ('issued', 'deploying', 'active', 'renewal_due', 'revoked')
           OR not_after IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot add issuance provenance after issued certificate order facts exist'
            USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM certificate_orders certificate_order
        JOIN access_scopes scope ON scope.id = certificate_order.scope_id
        LEFT JOIN tenants tenant ON tenant.id = scope.tenant_id
        LEFT JOIN memberships membership
          ON membership.scope_id = certificate_order.scope_id
         AND membership.user_id = certificate_order.created_by_user_id
        LEFT JOIN users account ON account.id = certificate_order.created_by_user_id
        WHERE scope.kind <> 'tenant'
           OR tenant.status IS DISTINCT FROM 'active'
           OR membership.status IS DISTINCT FROM 'active'
           OR account.status IS DISTINCT FROM 'active'
    ) THEN
        RAISE EXCEPTION 'cannot bind certificate orders without an active tenant actor'
            USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dns_acme_outbox
        WHERE status <> 'pending' OR attempts <> 0 OR completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot add leased delivery to an outbox with delivery history'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

CREATE TABLE acme_tenant_key_facts (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    id uuid NOT NULL,
    key_ref text NOT NULL CHECK (
        key_ref = btrim(key_ref)
        AND octet_length(key_ref) BETWEEN 1 AND 200
        AND key_ref !~ '[[:cntrl:]]'
    ),
    purpose text NOT NULL CHECK (purpose IN ('account', 'certificate')),
    algorithm text NOT NULL CHECK (algorithm IN ('rsa', 'ecdsa', 'ed25519')),
    public_key_spki_sha256 bytea NOT NULL CHECK (octet_length(public_key_spki_sha256) = 32),
    external_key_reference text CHECK (
        external_key_reference IS NULL OR (
            external_key_reference = btrim(external_key_reference)
            AND octet_length(external_key_reference) BETWEEN 1 AND 1024
            AND external_key_reference !~ '[[:cntrl:]]'
        )
    ),
    wrapped_key_ciphertext bytea,
    wrapping_key_id text CHECK (
        wrapping_key_id IS NULL OR (
            wrapping_key_id = btrim(wrapping_key_id)
            AND octet_length(wrapping_key_id) BETWEEN 1 AND 200
            AND wrapping_key_id !~ '[[:cntrl:]]'
        )
    ),
    wrapping_nonce bytea,
    wrapping_aad_sha256 bytea,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (tenant_scope_id, id),
    UNIQUE (tenant_scope_id, key_ref),
    UNIQUE (tenant_scope_id, public_key_spki_sha256),
    CONSTRAINT acme_tenant_key_facts_actor_fk_048
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (
            external_key_reference IS NOT NULL
            AND wrapped_key_ciphertext IS NULL
            AND wrapping_key_id IS NULL
            AND wrapping_nonce IS NULL
            AND wrapping_aad_sha256 IS NULL
        ) OR (
            external_key_reference IS NULL
            AND octet_length(wrapped_key_ciphertext) BETWEEN 16 AND 131072
            AND wrapping_key_id IS NOT NULL
            AND octet_length(wrapping_nonce) BETWEEN 8 AND 64
            AND octet_length(wrapping_aad_sha256) = 32
        )
    )
);

CREATE INDEX acme_tenant_key_facts_actor_idx
    ON acme_tenant_key_facts (tenant_scope_id, created_by_user_id);
CREATE UNIQUE INDEX acme_tenant_key_facts_external_ref_idx_048
    ON acme_tenant_key_facts (tenant_scope_id, external_key_reference)
    WHERE external_key_reference IS NOT NULL;

CREATE TABLE acme_account_registration_facts (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    id uuid NOT NULL,
    account_key_id uuid NOT NULL,
    directory_url text NOT NULL CHECK (
        directory_url LIKE 'https://%'
        AND octet_length(directory_url) BETWEEN 10 AND 4096
        AND directory_url !~ '[[:cntrl:]]'
    ),
    account_uri text NOT NULL CHECK (
        account_uri LIKE 'https://%'
        AND octet_length(account_uri) BETWEEN 10 AND 4096
        AND account_uri !~ '[[:cntrl:]]'
    ),
    contacts text[] NOT NULL DEFAULT '{}' CHECK (cardinality(contacts) <= 20),
    terms_agreed_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL,
    created_by_user_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, id),
    UNIQUE (tenant_scope_id, directory_url, account_key_id),
    UNIQUE (tenant_scope_id, directory_url, account_uri),
    CONSTRAINT acme_account_registration_key_fk_048
    FOREIGN KEY (tenant_scope_id, account_key_id)
        REFERENCES acme_tenant_key_facts(tenant_scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT acme_account_registration_actor_fk_048
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (registered_at >= terms_agreed_at)
);

CREATE INDEX acme_account_registration_facts_actor_idx
    ON acme_account_registration_facts (tenant_scope_id, created_by_user_id);
CREATE INDEX acme_account_registration_facts_key_idx_048
    ON acme_account_registration_facts (tenant_scope_id, account_key_id);

ALTER TABLE acme_issuance_operations
    ADD COLUMN certificate_order_id uuid NOT NULL,
    ADD COLUMN actor_user_id uuid NOT NULL,
    ADD COLUMN dns_provider_id uuid,
    ADD COLUMN account_key_ref text NOT NULL;

ALTER TABLE acme_issuance_operations
    ADD CONSTRAINT acme_issuance_operations_order_fk_048
        FOREIGN KEY (tenant_scope_id, certificate_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT acme_issuance_operations_actor_fk_048
        FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT acme_issuance_operations_provider_fk_048
        FOREIGN KEY (tenant_scope_id, dns_provider_id)
        REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT acme_issuance_operations_account_key_fk_048
        FOREIGN KEY (tenant_scope_id, account_key_ref)
        REFERENCES acme_tenant_key_facts(tenant_scope_id, key_ref) ON DELETE RESTRICT,
    ADD CONSTRAINT acme_issuance_operations_certificate_key_fk_048
        FOREIGN KEY (tenant_scope_id, certificate_key_ref)
        REFERENCES acme_tenant_key_facts(tenant_scope_id, key_ref) ON DELETE RESTRICT,
    ADD CONSTRAINT acme_issuance_operations_order_identity_048
        CHECK (operation_id = certificate_order_id::text),
    ADD CONSTRAINT acme_issuance_operations_request_binding_048 CHECK (
        request_snapshot ->> 'ActorUserID' = actor_user_id::text
        AND request_snapshot ->> 'AccountKeyRef' = account_key_ref
        AND request_snapshot ->> 'ProviderRef'
            IS NOT DISTINCT FROM COALESCE(dns_provider_id::text, '')
    ),
    ADD CONSTRAINT acme_issuance_operations_order_unique_048
        UNIQUE (tenant_scope_id, certificate_order_id);

CREATE INDEX acme_issuance_operations_actor_idx_048
    ON acme_issuance_operations (tenant_scope_id, actor_user_id);
CREATE INDEX acme_issuance_operations_provider_idx_048
    ON acme_issuance_operations (tenant_scope_id, dns_provider_id)
    WHERE dns_provider_id IS NOT NULL;
CREATE INDEX acme_issuance_operations_account_key_idx_048
    ON acme_issuance_operations (tenant_scope_id, account_key_ref);
CREATE INDEX acme_issuance_operations_certificate_key_idx_048
    ON acme_issuance_operations (tenant_scope_id, certificate_key_ref);

ALTER TABLE acme_issuance_challenge_events
    ADD COLUMN provider_ref text,
    ADD COLUMN remote_record_ref text,
    ADD COLUMN exact_value_sha256 bytea,
    ADD CONSTRAINT acme_issuance_challenge_publication_shape_048 CHECK (
        (provider_ref IS NULL OR (
            provider_ref = btrim(provider_ref)
            AND octet_length(provider_ref) BETWEEN 1 AND 200
            AND provider_ref !~ '[[:cntrl:]]'
        ))
        AND (remote_record_ref IS NULL OR (
            remote_record_ref = btrim(remote_record_ref)
            AND octet_length(remote_record_ref) BETWEEN 1 AND 1024
            AND remote_record_ref !~ '[[:cntrl:]]'
        ))
        AND (exact_value_sha256 IS NULL OR octet_length(exact_value_sha256) = 32)
        AND (
            (provider_ref IS NULL AND remote_record_ref IS NULL)
            OR
            (provider_ref IS NOT NULL AND remote_record_ref IS NOT NULL
                AND exact_value_sha256 IS NOT NULL)
        )
    );

CREATE INDEX acme_issuance_challenge_remote_ref_idx_048
    ON acme_issuance_challenge_events (tenant_scope_id, provider_ref, remote_record_ref)
    WHERE remote_record_ref IS NOT NULL;

ALTER TABLE certificate_orders
    ADD COLUMN issued_asset_id uuid,
    ADD COLUMN issued_asset_version_id uuid,
    ADD COLUMN issued_at timestamptz,
    ADD COLUMN leaf_fingerprint_sha256 bytea,
    ADD COLUMN leaf_spki_sha256 bytea,
    ADD COLUMN acme_directory_url text,
    ADD COLUMN acme_account_key_ref text,
    ADD COLUMN certificate_key_ref text,
    ADD COLUMN external_order_url text,
    ADD COLUMN authorization_urls_sha256 bytea,
    ADD COLUMN certificate_url text;

ALTER TABLE certificate_orders
    ADD CONSTRAINT certificate_orders_issued_asset_fk_048
        FOREIGN KEY (scope_id, issued_asset_id, issued_asset_version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_orders_created_actor_fk_048
        FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_orders_updated_actor_fk_048
        FOREIGN KEY (scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_orders_issuance_contract_048 CHECK (
        (
            status IN ('pending', 'validating', 'issuing')
            AND not_after IS NULL
            AND issued_asset_id IS NULL AND issued_asset_version_id IS NULL
            AND issued_at IS NULL
            AND leaf_fingerprint_sha256 IS NULL AND leaf_spki_sha256 IS NULL
            AND acme_directory_url IS NULL AND acme_account_key_ref IS NULL
            AND certificate_key_ref IS NULL AND external_order_url IS NULL
            AND authorization_urls_sha256 IS NULL AND certificate_url IS NULL
        ) OR (
            status IN ('issued', 'deploying', 'active', 'renewal_due', 'revoked')
            AND not_after IS NOT NULL
            AND issued_asset_id IS NOT NULL AND issued_asset_version_id IS NOT NULL
            AND issued_at IS NOT NULL
            AND octet_length(leaf_fingerprint_sha256) = 32
            AND octet_length(leaf_spki_sha256) = 32
            AND acme_directory_url IS NOT NULL AND acme_account_key_ref IS NOT NULL
            AND certificate_key_ref IS NOT NULL AND external_order_url IS NOT NULL
            AND octet_length(authorization_urls_sha256) = 32
            AND certificate_url IS NOT NULL
        ) OR (
            status = 'failed' AND (
                (
                    not_after IS NULL
                    AND issued_asset_id IS NULL AND issued_asset_version_id IS NULL
                    AND issued_at IS NULL
                    AND leaf_fingerprint_sha256 IS NULL AND leaf_spki_sha256 IS NULL
                    AND acme_directory_url IS NULL AND acme_account_key_ref IS NULL
                    AND certificate_key_ref IS NULL AND external_order_url IS NULL
                    AND authorization_urls_sha256 IS NULL AND certificate_url IS NULL
                ) OR (
                    not_after IS NOT NULL
                    AND issued_asset_id IS NOT NULL AND issued_asset_version_id IS NOT NULL
                    AND issued_at IS NOT NULL
                    AND octet_length(leaf_fingerprint_sha256) = 32
                    AND octet_length(leaf_spki_sha256) = 32
                    AND acme_directory_url IS NOT NULL AND acme_account_key_ref IS NOT NULL
                    AND certificate_key_ref IS NOT NULL AND external_order_url IS NOT NULL
                    AND octet_length(authorization_urls_sha256) = 32
                    AND certificate_url IS NOT NULL
                )
            )
        )
    ),
    ADD CONSTRAINT certificate_orders_issuance_urls_048 CHECK (
        (acme_directory_url IS NULL OR (
            acme_directory_url LIKE 'https://%'
            AND octet_length(acme_directory_url) <= 4096
            AND acme_directory_url !~ '[[:cntrl:]]'
        ))
        AND (external_order_url IS NULL OR (
            external_order_url LIKE 'https://%'
            AND octet_length(external_order_url) <= 4096
            AND external_order_url !~ '[[:cntrl:]]'
        ))
        AND (certificate_url IS NULL OR (
            certificate_url LIKE 'https://%'
            AND octet_length(certificate_url) <= 4096
            AND certificate_url !~ '[[:cntrl:]]'
        ))
    ),
    ADD CONSTRAINT certificate_orders_issuance_refs_048 CHECK (
        (acme_account_key_ref IS NULL OR (
            acme_account_key_ref = btrim(acme_account_key_ref)
            AND octet_length(acme_account_key_ref) BETWEEN 1 AND 200
            AND acme_account_key_ref !~ '[[:cntrl:]]'
        ))
        AND (certificate_key_ref IS NULL OR (
            certificate_key_ref = btrim(certificate_key_ref)
            AND octet_length(certificate_key_ref) BETWEEN 1 AND 200
            AND certificate_key_ref !~ '[[:cntrl:]]'
        ))
    );

CREATE INDEX certificate_orders_issued_asset_idx_048
    ON certificate_orders (scope_id, issued_asset_id, issued_asset_version_id)
    WHERE issued_asset_id IS NOT NULL;
CREATE INDEX certificate_orders_created_actor_idx_048
    ON certificate_orders (scope_id, created_by_user_id);
CREATE INDEX certificate_orders_updated_actor_idx_048
    ON certificate_orders (scope_id, updated_by_user_id);

ALTER TABLE dns_acme_outbox
    ADD COLUMN lease_token uuid,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN last_error_code text CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z0-9_]{1,128}$'
    ),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    ADD CONSTRAINT dns_acme_outbox_lease_contract_048 CHECK (
        updated_at >= created_at
        AND (
            (
                status = 'pending' AND attempts = 0
                AND lease_token IS NULL AND lease_expires_at IS NULL
                AND last_error_code IS NULL AND completed_at IS NULL
            ) OR (
                status = 'processing' AND attempts > 0
                AND lease_token IS NOT NULL AND lease_expires_at > updated_at
                AND last_error_code IS NULL AND completed_at IS NULL
            ) OR (
                status = 'failed' AND attempts > 0
                AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                AND last_error_code IS NOT NULL AND completed_at IS NULL
                AND next_attempt_at > updated_at
            ) OR (
                status = 'completed' AND attempts > 0
                AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                AND last_error_code IS NULL AND completed_at = updated_at
            )
        )
    );

DROP INDEX dns_acme_outbox_pending_idx;
CREATE INDEX dns_acme_outbox_claim_idx_048
    ON dns_acme_outbox (next_attempt_at, created_at, id)
    WHERE status IN ('pending', 'failed');
CREATE INDEX dns_acme_outbox_takeover_idx_048
    ON dns_acme_outbox (lease_expires_at, created_at, id)
    WHERE status = 'processing';
CREATE INDEX dns_acme_outbox_order_idx_048
    ON dns_acme_outbox (scope_id, aggregate_id);

CREATE TABLE acme_renewal_claim_facts (
    tenant_scope_id uuid NOT NULL,
    source_order_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    actor_user_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'claim_created', 'lease_taken_over', 'retry_scheduled', 'completed'
    )),
    status text NOT NULL CHECK (status IN ('active', 'retry_wait', 'completed')),
    fence_token uuid NOT NULL,
    lease_token uuid,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9_]{1,128}$'),
    renewal_order_id uuid,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, source_order_id, revision),
    CONSTRAINT acme_renewal_claim_source_order_fk_048
    FOREIGN KEY (tenant_scope_id, source_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT acme_renewal_claim_result_order_fk_048
    FOREIGN KEY (tenant_scope_id, renewal_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT acme_renewal_claim_actor_fk_048
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (
            status = 'active'
            AND lease_token IS NOT NULL AND fence_token = lease_token
            AND lease_expires_at > occurred_at
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NULL
        ) OR (
            status = 'retry_wait'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at > occurred_at AND failure_code IS NOT NULL
            AND renewal_order_id IS NULL
        ) OR (
            status = 'completed'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX acme_renewal_claim_completed_order_idx_048
    ON acme_renewal_claim_facts (tenant_scope_id, renewal_order_id)
    WHERE renewal_order_id IS NOT NULL;
CREATE INDEX acme_renewal_claim_reconcile_idx_048
    ON acme_renewal_claim_facts (status, next_attempt_at, lease_expires_at, occurred_at)
    INCLUDE (tenant_scope_id, source_order_id, revision);
CREATE INDEX acme_renewal_claim_actor_idx_048
    ON acme_renewal_claim_facts (tenant_scope_id, actor_user_id);

CREATE FUNCTION reject_dns_acme_runtime_fact_mutation_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'DNS ACME runtime facts are immutable' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION acme_runtime_actor_is_active_048(scope_id uuid, actor_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id
         AND membership.user_id = actor_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        WHERE scope.id = scope_id AND scope.kind = 'tenant'
    )
$$;

CREATE FUNCTION validate_acme_tenant_key_fact_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.created_by_user_id) THEN
        RAISE EXCEPTION 'ACME key fact requires an active tenant actor' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_account_registration_fact_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.created_by_user_id)
       OR NOT EXISTS (
           SELECT 1 FROM acme_tenant_key_facts key
           WHERE key.tenant_scope_id = NEW.tenant_scope_id
             AND key.id = NEW.account_key_id
             AND key.purpose = 'account'
       ) THEN
        RAISE EXCEPTION 'ACME account fact requires an active actor and account key'
            USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (
        SELECT 1 FROM unnest(NEW.contacts) contact
        WHERE contact IS NULL
           OR contact <> btrim(contact)
           OR octet_length(contact) NOT BETWEEN 1 AND 512
           OR contact !~ '^mailto:[^[:space:][:cntrl:]]+@[^[:space:][:cntrl:]]+$'
    ) OR cardinality(NEW.contacts) <> (
        SELECT count(DISTINCT contact) FROM unnest(NEW.contacts) contact
    ) THEN
        RAISE EXCEPTION 'ACME account contact is invalid' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_operation_binding_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    order_row certificate_orders%ROWTYPE;
    account_purpose text;
    certificate_purpose text;
BEGIN
    SELECT * INTO order_row
    FROM certificate_orders
    WHERE scope_id = NEW.tenant_scope_id AND id = NEW.certificate_order_id
    FOR UPDATE;
    IF NOT FOUND
       OR NOT EXISTS (
           SELECT 1
           FROM access_scopes scope
           JOIN tenants tenant
             ON tenant.id = scope.tenant_id
            AND tenant.status = 'active'
           WHERE scope.id = NEW.tenant_scope_id
             AND scope.kind = 'tenant'
             AND NEW.request_snapshot ->> 'ScopeID' = scope.id::text
             AND NEW.request_snapshot ->> 'TenantID' = tenant.id::text
       )
       OR order_row.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
       OR order_row.dns_provider_id IS DISTINCT FROM NEW.dns_provider_id
       OR order_row.status NOT IN ('pending', 'validating', 'issuing')
       OR NEW.request_snapshot -> 'Domains' IS DISTINCT FROM to_jsonb(order_row.domains)
       OR NEW.request_snapshot ->> 'ChallengeType' IS DISTINCT FROM order_row.challenge_type
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.actor_user_id) THEN
        RAISE EXCEPTION 'ACME operation is not bound to an active certificate order actor'
            USING ERRCODE = 'P0001';
    END IF;
    IF order_row.challenge_type = 'dns-01' AND NOT EXISTS (
        SELECT 1 FROM dns_providers provider
        WHERE provider.scope_id = NEW.tenant_scope_id
          AND provider.id = NEW.dns_provider_id
          AND provider.status = 'verified'
    ) THEN
        RAISE EXCEPTION 'DNS-01 operation requires a verified tenant DNS provider'
            USING ERRCODE = 'P0001';
    END IF;
    SELECT purpose INTO account_purpose
    FROM acme_tenant_key_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND key_ref = NEW.account_key_ref;
    SELECT purpose INTO certificate_purpose
    FROM acme_tenant_key_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND key_ref = NEW.certificate_key_ref;
    IF account_purpose IS DISTINCT FROM 'account'
       OR certificate_purpose IS DISTINCT FROM 'certificate' THEN
        RAISE EXCEPTION 'ACME operation key purposes are invalid' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_operation_event_runtime_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_row acme_issuance_operations%ROWTYPE;
BEGIN
    SELECT * INTO operation_row
    FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id;
    IF NEW.account_uri IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM acme_account_registration_facts account
        JOIN acme_tenant_key_facts key
          ON key.tenant_scope_id = account.tenant_scope_id
         AND key.id = account.account_key_id
        WHERE account.tenant_scope_id = NEW.tenant_scope_id
          AND account.directory_url = operation_row.directory_url
          AND account.account_uri = NEW.account_uri
          AND key.key_ref = operation_row.account_key_ref
    ) THEN
        RAISE EXCEPTION 'ACME operation account URI has no tenant registration fact'
            USING ERRCODE = 'P0001';
    END IF;
    IF NEW.event_type IN ('certificate_saved', 'completed') AND NOT EXISTS (
        SELECT 1
        FROM certificate_asset_versions version
        JOIN certificate_orders certificate_order
          ON certificate_order.scope_id = version.tenant_scope_id
         AND certificate_order.id = version.acme_order_id
        WHERE version.tenant_scope_id = NEW.tenant_scope_id
          AND version.acme_order_id = operation_row.certificate_order_id
          AND version.fingerprint_sha256 = NEW.leaf_fingerprint_sha256
          AND version.public_key_sha256 = NEW.certificate_spki_sha256
          AND certificate_order.status IN ('issued', 'deploying', 'active', 'renewal_due', 'revoked')
          AND certificate_order.issued_asset_id = version.asset_id
          AND certificate_order.issued_asset_version_id = version.id
          AND certificate_order.external_order_url = NEW.order_url
          AND certificate_order.certificate_url = NEW.certificate_url
          AND certificate_order.acme_directory_url = operation_row.directory_url
          AND certificate_order.acme_account_key_ref = operation_row.account_key_ref
          AND certificate_order.certificate_key_ref = operation_row.certificate_key_ref
    ) THEN
        RAISE EXCEPTION 'saved ACME certificate has no matching asset version fact'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_challenge_publication_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    attempt acme_issuance_challenge_attempts%ROWTYPE;
    previous acme_issuance_challenge_events%ROWTYPE;
    frozen_provider text;
    expected_digest bytea;
BEGIN
    SELECT * INTO attempt
    FROM acme_issuance_challenge_attempts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND attempt_id = NEW.attempt_id;
    SELECT request_snapshot ->> 'ProviderRef' INTO frozen_provider
    FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id;

    IF attempt.challenge_type = 'http-01' THEN
        IF NEW.provider_ref IS NOT NULL OR NEW.remote_record_ref IS NOT NULL
           OR NEW.exact_value_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'HTTP-01 challenge cannot carry DNS publication facts'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    expected_digest := sha256(convert_to(attempt.exact_value, 'UTF8'));
    IF NEW.exact_value_sha256 IS DISTINCT FROM expected_digest
       OR (NEW.state = 'intent' AND (
           NEW.provider_ref IS NOT NULL OR NEW.remote_record_ref IS NOT NULL
       ))
       OR (NEW.state <> 'intent' AND (
           NEW.provider_ref IS DISTINCT FROM frozen_provider OR NEW.remote_record_ref IS NULL
       )) THEN
        RAISE EXCEPTION 'DNS-01 publication fact is incomplete or mismatched'
            USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision > 1 THEN
        SELECT * INTO previous
        FROM acme_issuance_challenge_events
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND operation_id = NEW.operation_id
          AND attempt_id = NEW.attempt_id
          AND revision = NEW.revision - 1;
        IF NEW.exact_value_sha256 IS DISTINCT FROM previous.exact_value_sha256
           OR (previous.state <> 'intent' AND (
               NEW.provider_ref IS DISTINCT FROM previous.provider_ref
               OR NEW.remote_record_ref IS DISTINCT FROM previous.remote_record_ref
           )) THEN
            RAISE EXCEPTION 'DNS-01 remote record handle is immutable after publication'
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    IF NEW.remote_record_ref IS NOT NULL AND EXISTS (
        SELECT 1 FROM acme_issuance_challenge_events other
        WHERE other.tenant_scope_id = NEW.tenant_scope_id
          AND other.provider_ref = NEW.provider_ref
          AND other.remote_record_ref = NEW.remote_record_ref
          AND (other.operation_id, other.attempt_id)
              IS DISTINCT FROM (NEW.operation_id, NEW.attempt_id)
    ) THEN
        RAISE EXCEPTION 'DNS remote record handle is already bound to another challenge'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_certificate_order_runtime_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    asset_version certificate_asset_versions%ROWTYPE;
    operation_row acme_issuance_operations%ROWTYPE;
    operation_event acme_issuance_operation_events%ROWTYPE;
    expected_authorization_digest bytea;
    transition_allowed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.revision <> 1
           OR NEW.not_after IS NOT NULL OR NEW.failure_code IS NOT NULL
           OR NEW.issued_asset_id IS NOT NULL OR NEW.issued_asset_version_id IS NOT NULL
           OR NEW.issued_at IS NOT NULL OR NEW.leaf_fingerprint_sha256 IS NOT NULL
           OR NEW.leaf_spki_sha256 IS NOT NULL OR NEW.acme_directory_url IS NOT NULL
           OR NEW.acme_account_key_ref IS NOT NULL OR NEW.certificate_key_ref IS NOT NULL
           OR NEW.external_order_url IS NOT NULL OR NEW.authorization_urls_sha256 IS NOT NULL
           OR NEW.certificate_url IS NOT NULL THEN
            RAISE EXCEPTION 'certificate order must start pending without issuance facts'
                USING ERRCODE = 'P0001';
        END IF;
        IF NOT acme_runtime_actor_is_active_048(NEW.scope_id, NEW.created_by_user_id) THEN
            RAISE EXCEPTION 'certificate order requires an active tenant actor'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'certificate orders cannot be removed' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
       OR NEW.dns_provider_id IS DISTINCT FROM OLD.dns_provider_id
       OR NEW.domains IS DISTINCT FROM OLD.domains
       OR NEW.challenge_type IS DISTINCT FROM OLD.challenge_type
       OR NEW.auto_renew IS DISTINCT FROM OLD.auto_renew
       OR NEW.renewal_of_order_id IS DISTINCT FROM OLD.renewal_of_order_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.updated_by_user_id IS DISTINCT FROM OLD.updated_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'certificate order identity or revision is immutable'
            USING ERRCODE = 'P0001';
    END IF;
    transition_allowed := CASE OLD.status
        WHEN 'pending' THEN NEW.status IN ('validating', 'failed')
        WHEN 'validating' THEN NEW.status IN ('issuing', 'failed')
        WHEN 'issuing' THEN NEW.status IN ('issued', 'failed')
        WHEN 'issued' THEN NEW.status = 'deploying'
        WHEN 'deploying' THEN NEW.status IN ('active', 'failed')
        WHEN 'active' THEN NEW.status IN ('renewal_due', 'revoked')
        WHEN 'renewal_due' THEN NEW.status = 'revoked'
        ELSE false
    END;
    IF NOT transition_allowed THEN
        RAISE EXCEPTION 'certificate order state transition is not monotonic'
            USING ERRCODE = 'P0001';
    END IF;

    IF OLD.issued_at IS NOT NULL THEN
        IF ROW(
            NEW.not_after, NEW.issued_asset_id, NEW.issued_asset_version_id, NEW.issued_at,
            NEW.leaf_fingerprint_sha256, NEW.leaf_spki_sha256, NEW.acme_directory_url,
            NEW.acme_account_key_ref, NEW.certificate_key_ref, NEW.external_order_url,
            NEW.authorization_urls_sha256, NEW.certificate_url
        ) IS DISTINCT FROM ROW(
            OLD.not_after, OLD.issued_asset_id, OLD.issued_asset_version_id, OLD.issued_at,
            OLD.leaf_fingerprint_sha256, OLD.leaf_spki_sha256, OLD.acme_directory_url,
            OLD.acme_account_key_ref, OLD.certificate_key_ref, OLD.external_order_url,
            OLD.authorization_urls_sha256, OLD.certificate_url
        ) THEN
            RAISE EXCEPTION 'certificate order issuance provenance is immutable'
                USING ERRCODE = 'P0001';
        END IF;
    ELSIF OLD.status = 'issuing' AND NEW.status = 'issued' THEN
        SELECT * INTO asset_version
        FROM certificate_asset_versions
        WHERE tenant_scope_id = NEW.scope_id
          AND asset_id = NEW.issued_asset_id
          AND id = NEW.issued_asset_version_id;
        SELECT * INTO operation_row
        FROM acme_issuance_operations
        WHERE tenant_scope_id = NEW.scope_id
          AND certificate_order_id = NEW.id;
        SELECT * INTO operation_event
        FROM acme_issuance_operation_events
        WHERE tenant_scope_id = NEW.scope_id
          AND operation_id = operation_row.operation_id
        ORDER BY revision DESC LIMIT 1;
        SELECT sha256(string_agg(
            convert_to(value, 'UTF8') || decode('00', 'hex'),
            ''::bytea ORDER BY value
        )) INTO expected_authorization_digest
        FROM unnest(operation_event.authorization_urls) value;
        IF asset_version.id IS NULL
           OR asset_version.acme_order_id IS DISTINCT FROM NEW.id
           OR asset_version.fingerprint_sha256 IS DISTINCT FROM NEW.leaf_fingerprint_sha256
           OR asset_version.public_key_sha256 IS DISTINCT FROM NEW.leaf_spki_sha256
           OR asset_version.private_key_reference IS DISTINCT FROM NEW.certificate_key_ref
           OR asset_version.not_after IS DISTINCT FROM NEW.not_after
           OR asset_version.sans IS DISTINCT FROM NEW.domains
           OR NEW.issued_at < NEW.created_at OR NEW.issued_at >= NEW.not_after
           OR operation_row.certificate_order_id IS NULL
           OR operation_row.directory_url IS DISTINCT FROM NEW.acme_directory_url
           OR operation_row.account_key_ref IS DISTINCT FROM NEW.acme_account_key_ref
           OR operation_row.certificate_key_ref IS DISTINCT FROM NEW.certificate_key_ref
           OR operation_event.status IS DISTINCT FROM 'active'
           OR operation_event.phase IS DISTINCT FROM 'finalizing'
           OR operation_event.lease_expires_at <= statement_timestamp()
           OR operation_event.account_uri IS NULL
           OR operation_event.order_url IS DISTINCT FROM NEW.external_order_url
           OR expected_authorization_digest IS DISTINCT FROM NEW.authorization_urls_sha256
           OR NOT EXISTS (
               SELECT 1 FROM acme_tenant_key_facts key
               WHERE key.tenant_scope_id = NEW.scope_id
                 AND key.key_ref = NEW.certificate_key_ref
                 AND key.purpose = 'certificate'
                 AND key.public_key_spki_sha256 = NEW.leaf_spki_sha256
           )
           OR NOT acme_runtime_actor_is_active_048(NEW.scope_id, operation_row.actor_user_id) THEN
            RAISE EXCEPTION 'certificate order issuance provenance does not match runtime facts'
                USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.not_after IS NOT NULL
          OR NEW.issued_asset_id IS NOT NULL OR NEW.issued_asset_version_id IS NOT NULL
          OR NEW.issued_at IS NOT NULL OR NEW.leaf_fingerprint_sha256 IS NOT NULL
          OR NEW.leaf_spki_sha256 IS NOT NULL OR NEW.acme_directory_url IS NOT NULL
          OR NEW.acme_account_key_ref IS NOT NULL OR NEW.certificate_key_ref IS NOT NULL
          OR NEW.external_order_url IS NOT NULL OR NEW.authorization_urls_sha256 IS NOT NULL
          OR NEW.certificate_url IS NOT NULL THEN
        RAISE EXCEPTION 'issuance provenance is accepted only when issuing becomes issued'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_dns_acme_outbox_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now timestamptz := statement_timestamp();
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.attempts <> 0
           OR NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL
           OR NEW.last_error_code IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'DNS ACME outbox must start pending without lease history'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' OR OLD.status = 'completed'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.updated_at IS DISTINCT FROM database_now THEN
        RAISE EXCEPTION 'DNS ACME outbox immutable fields or database clock were changed'
            USING ERRCODE = 'P0001';
    END IF;

    IF NEW.status = 'processing' THEN
        IF NEW.attempts <> OLD.attempts + 1
           OR NEW.lease_token IS NULL
           OR NEW.lease_token IS NOT DISTINCT FROM OLD.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NEW.last_error_code IS NOT NULL OR NEW.completed_at IS NOT NULL
           OR NEW.next_attempt_at IS DISTINCT FROM OLD.next_attempt_at
           OR NOT (
               (OLD.status IN ('pending', 'failed') AND OLD.next_attempt_at <= database_now)
               OR (OLD.status = 'processing' AND OLD.lease_expires_at <= database_now)
           ) THEN
            RAISE EXCEPTION 'DNS ACME outbox claim or lease takeover was rejected'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status <> 'processing'
       OR OLD.lease_expires_at <= database_now
       OR NEW.attempts IS DISTINCT FROM OLD.attempts
       OR NEW.lease_token IS DISTINCT FROM OLD.lease_token
       OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at THEN
        RAISE EXCEPTION 'DNS ACME outbox lease fence rejected the result'
            USING ERRCODE = 'P0001';
    END IF;
    IF NEW.status = 'completed' THEN
        IF NEW.completed_at IS DISTINCT FROM database_now
           OR NEW.last_error_code IS NOT NULL
           OR NEW.next_attempt_at IS DISTINCT FROM OLD.next_attempt_at THEN
            RAISE EXCEPTION 'DNS ACME outbox completion is invalid' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status = 'failed' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.last_error_code IS NULL
           OR NEW.next_attempt_at <= database_now THEN
            RAISE EXCEPTION 'DNS ACME outbox retry schedule is invalid' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'DNS ACME outbox transition is invalid' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION validate_acme_renewal_claim_fact_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_order certificate_orders%ROWTYPE;
    previous acme_renewal_claim_facts%ROWTYPE;
    renewal_order certificate_orders%ROWTYPE;
    database_now timestamptz := statement_timestamp();
BEGIN
    SELECT * INTO source_order
    FROM certificate_orders
    WHERE scope_id = NEW.tenant_scope_id AND id = NEW.source_order_id
    FOR UPDATE;
    IF source_order.id IS NULL
       OR NOT source_order.auto_renew
       OR source_order.status NOT IN ('active', 'renewal_due')
       OR source_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.actor_user_id)
       OR NEW.occurred_at < database_now - interval '5 minutes'
       OR NEW.occurred_at > database_now + interval '1 minute' THEN
        RAISE EXCEPTION 'ACME renewal claim source or actor is invalid' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision = 1 THEN
        IF NEW.event_type <> 'claim_created' OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now THEN
            RAISE EXCEPTION 'invalid initial ACME renewal claim' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO previous
    FROM acme_renewal_claim_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND source_order_id = NEW.source_order_id
      AND revision = NEW.revision - 1;
    IF NOT FOUND OR previous.status = 'completed' OR NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME renewal claim revision is not contiguous'
            USING ERRCODE = 'P0001';
    END IF;

    IF NEW.event_type = 'lease_taken_over' THEN
        IF NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_token IS NOT DISTINCT FROM previous.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NOT (
               (previous.status = 'active' AND previous.lease_expires_at <= database_now)
               OR (previous.status = 'retry_wait' AND previous.next_attempt_at <= database_now)
           ) THEN
            RAISE EXCEPTION 'invalid ACME renewal lease takeover' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF previous.status <> 'active' OR previous.lease_expires_at <= database_now
       OR NEW.fence_token IS DISTINCT FROM previous.lease_token THEN
        RAISE EXCEPTION 'ACME renewal lease fence rejected the event'
            USING ERRCODE = 'P0001';
    END IF;
    IF NEW.event_type = 'retry_scheduled' THEN
        IF NEW.status <> 'retry_wait' THEN
            RAISE EXCEPTION 'invalid ACME renewal retry event' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.event_type = 'completed' AND NEW.status = 'completed' THEN
        SELECT * INTO renewal_order
        FROM certificate_orders
        WHERE scope_id = NEW.tenant_scope_id AND id = NEW.renewal_order_id;
        IF renewal_order.id IS NULL
           OR renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id
           OR renewal_order.status IS DISTINCT FROM 'pending'
           OR renewal_order.dns_provider_id IS DISTINCT FROM source_order.dns_provider_id
           OR renewal_order.domains IS DISTINCT FROM source_order.domains
           OR renewal_order.challenge_type IS DISTINCT FROM source_order.challenge_type
           OR renewal_order.auto_renew IS DISTINCT FROM source_order.auto_renew
           OR renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'ACME renewal claim result is not a child order'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid ACME renewal claim event' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER acme_tenant_key_facts_validate_048
BEFORE INSERT ON acme_tenant_key_facts
FOR EACH ROW EXECUTE FUNCTION validate_acme_tenant_key_fact_048();
CREATE TRIGGER acme_tenant_key_facts_immutable_048
BEFORE UPDATE OR DELETE ON acme_tenant_key_facts
FOR EACH ROW EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();
CREATE TRIGGER acme_tenant_key_facts_no_truncate_048
BEFORE TRUNCATE ON acme_tenant_key_facts
FOR EACH STATEMENT EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();

CREATE TRIGGER acme_account_registration_facts_validate_048
BEFORE INSERT ON acme_account_registration_facts
FOR EACH ROW EXECUTE FUNCTION validate_acme_account_registration_fact_048();
CREATE TRIGGER acme_account_registration_facts_immutable_048
BEFORE UPDATE OR DELETE ON acme_account_registration_facts
FOR EACH ROW EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();
CREATE TRIGGER acme_account_registration_facts_no_truncate_048
BEFORE TRUNCATE ON acme_account_registration_facts
FOR EACH STATEMENT EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();

CREATE TRIGGER acme_issuance_operations_binding_048
BEFORE INSERT ON acme_issuance_operations
FOR EACH ROW EXECUTE FUNCTION validate_acme_operation_binding_048();
CREATE TRIGGER acme_issuance_operation_events_runtime_048
BEFORE INSERT ON acme_issuance_operation_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_operation_event_runtime_048();
CREATE TRIGGER acme_issuance_challenge_publication_048
BEFORE INSERT ON acme_issuance_challenge_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_challenge_publication_048();

CREATE TRIGGER certificate_orders_runtime_048
BEFORE INSERT OR UPDATE OR DELETE ON certificate_orders
FOR EACH ROW EXECUTE FUNCTION protect_certificate_order_runtime_048();
CREATE TRIGGER certificate_orders_no_truncate_048
BEFORE TRUNCATE ON certificate_orders
FOR EACH STATEMENT EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();

CREATE TRIGGER dns_acme_outbox_runtime_048
BEFORE INSERT OR UPDATE OR DELETE ON dns_acme_outbox
FOR EACH ROW EXECUTE FUNCTION protect_dns_acme_outbox_048();
CREATE TRIGGER dns_acme_outbox_no_truncate_048
BEFORE TRUNCATE ON dns_acme_outbox
FOR EACH STATEMENT EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();

CREATE TRIGGER acme_renewal_claim_facts_validate_048
BEFORE INSERT ON acme_renewal_claim_facts
FOR EACH ROW EXECUTE FUNCTION validate_acme_renewal_claim_fact_048();
CREATE TRIGGER acme_renewal_claim_facts_immutable_048
BEFORE UPDATE OR DELETE ON acme_renewal_claim_facts
FOR EACH ROW EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();
CREATE TRIGGER acme_renewal_claim_facts_no_truncate_048
BEFORE TRUNCATE ON acme_renewal_claim_facts
FOR EACH STATEMENT EXECUTE FUNCTION reject_dns_acme_runtime_fact_mutation_048();

ALTER TABLE acme_tenant_key_facts ENABLE ALWAYS TRIGGER acme_tenant_key_facts_validate_048;
ALTER TABLE acme_tenant_key_facts ENABLE ALWAYS TRIGGER acme_tenant_key_facts_immutable_048;
ALTER TABLE acme_tenant_key_facts ENABLE ALWAYS TRIGGER acme_tenant_key_facts_no_truncate_048;
ALTER TABLE acme_account_registration_facts ENABLE ALWAYS TRIGGER acme_account_registration_facts_validate_048;
ALTER TABLE acme_account_registration_facts ENABLE ALWAYS TRIGGER acme_account_registration_facts_immutable_048;
ALTER TABLE acme_account_registration_facts ENABLE ALWAYS TRIGGER acme_account_registration_facts_no_truncate_048;
ALTER TABLE acme_issuance_operations ENABLE ALWAYS TRIGGER acme_issuance_operations_binding_048;
ALTER TABLE acme_issuance_operation_events ENABLE ALWAYS TRIGGER acme_issuance_operation_events_runtime_048;
ALTER TABLE acme_issuance_challenge_events ENABLE ALWAYS TRIGGER acme_issuance_challenge_publication_048;
ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_runtime_048;
ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_no_truncate_048;
ALTER TABLE dns_acme_outbox ENABLE ALWAYS TRIGGER dns_acme_outbox_runtime_048;
ALTER TABLE dns_acme_outbox ENABLE ALWAYS TRIGGER dns_acme_outbox_no_truncate_048;
ALTER TABLE acme_renewal_claim_facts ENABLE ALWAYS TRIGGER acme_renewal_claim_facts_validate_048;
ALTER TABLE acme_renewal_claim_facts ENABLE ALWAYS TRIGGER acme_renewal_claim_facts_immutable_048;
ALTER TABLE acme_renewal_claim_facts ENABLE ALWAYS TRIGGER acme_renewal_claim_facts_no_truncate_048;
