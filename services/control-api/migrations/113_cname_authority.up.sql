LOCK TABLE schema_migrations,
    dns_zones,
    dns_providers,
    sites,
    package_subscriptions,
    package_monitor_subscription_owners,
    package_order_fulfillments,
    package_orders,
    background_jobs,
    memberships,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 112 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 112 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=112 AND migration_id='112_dns_reconcile_actor_receipts'
          AND checksum_sha256='d26988f21844ba759a0345ad1aed1fd3d40156c6a22dd2e382736987348a8017'
          AND down_checksum_sha256='d329f963d275aad130595d2e4f477e9cfd5416e06bec2761e78760db8f4f1aa0'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 113 requires the exact verified 112 release head' USING ERRCODE='P1130';
    END IF;
END;
$$;

ALTER TABLE dns_zones
    ADD COLUMN is_default boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT dns_zones_scope_zone_provider_name_113_key UNIQUE (scope_id,id,provider_id,name);

CREATE UNIQUE INDEX dns_zones_scope_default_113_uidx
    ON dns_zones (scope_id) WHERE is_default;

ALTER TABLE package_subscriptions
    ADD CONSTRAINT package_subscriptions_scope_id_product_113_key UNIQUE (tenant_scope_id,id,product_id);

ALTER TABLE sites
    ADD CONSTRAINT sites_scope_id_owner_113_key UNIQUE (scope_id,id,owner_user_id),
    ADD COLUMN package_subscription_id uuid,
    ADD COLUMN cname_mode text,
    ADD COLUMN cname_domain text,
    ADD COLUMN cname_hostname2 text,
    ADD COLUMN cname_state text,
    ADD COLUMN cname_task_id uuid,
    ADD COLUMN cname_current_revision bigint,
    ADD COLUMN cname_lkg_revision bigint;

WITH exact_fulfilled_binding AS (
    SELECT site.id AS site_id,
           min(owner.subscription_id::text)::uuid AS package_subscription_id
    FROM sites AS site
    JOIN package_monitor_subscription_owners AS owner
      ON owner.tenant_scope_id=site.scope_id
     AND owner.owner_user_id=site.owner_user_id
     AND owner.source_kind='commerce_fulfillment'
     AND owner.source_fulfillment_id IS NOT NULL
    JOIN package_subscriptions AS subscription
      ON subscription.tenant_scope_id=site.scope_id
     AND subscription.id=owner.subscription_id
     AND subscription.product_id=site.package_id
    JOIN package_order_fulfillments AS fulfillment
      ON fulfillment.id=owner.source_fulfillment_id
     AND fulfillment.tenant_scope_id=site.scope_id
     AND fulfillment.subscription_id=owner.subscription_id
    JOIN package_orders AS package_order
      ON package_order.id=fulfillment.order_id
     AND package_order.tenant_scope_id=site.scope_id
     AND package_order.user_id=site.owner_user_id
     AND package_order.product_kind='package_subscription'
     AND package_order.product_id=site.package_id
     AND (package_order.subscription_id IS NULL OR package_order.subscription_id=owner.subscription_id)
    WHERE site.package_id IS NOT NULL
    GROUP BY site.id
    HAVING count(*)=1 AND count(DISTINCT owner.subscription_id)=1
)
UPDATE sites AS site
SET package_subscription_id=binding.package_subscription_id
FROM exact_fulfilled_binding AS binding
WHERE site.id=binding.site_id;

ALTER TABLE sites
    ADD CONSTRAINT sites_scope_package_subscription_product_113_fk
        FOREIGN KEY (scope_id,package_subscription_id,package_id)
        REFERENCES package_subscriptions(tenant_scope_id,id,product_id) ON DELETE RESTRICT,
    ADD CONSTRAINT sites_package_subscription_owner_113_fk
        FOREIGN KEY (package_subscription_id,scope_id,owner_user_id)
        REFERENCES package_monitor_subscription_owners(subscription_id,tenant_scope_id,owner_user_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT sites_cname_task_113_fk
        FOREIGN KEY (cname_task_id) REFERENCES background_jobs(id) ON DELETE RESTRICT,
    ADD CONSTRAINT sites_cname_projection_113_check CHECK (
        package_subscription_id IS NULL OR package_id IS NOT NULL
    ),
    ADD CONSTRAINT sites_cname_mode_113_check CHECK (
        cname_mode IS NULL OR cname_mode IN ('site','package')
    ),
    ADD CONSTRAINT sites_cname_domain_113_check CHECK (
        cname_domain IS NULL OR (
            cname_domain=lower(btrim(cname_domain)) AND char_length(cname_domain) <= 253
        )
    ),
    ADD CONSTRAINT sites_cname_hostname2_113_check CHECK (
        cname_hostname2 IS NULL OR (
            cname_hostname2=lower(btrim(cname_hostname2)) AND char_length(cname_hostname2) <= 253
        )
    ),
    ADD CONSTRAINT sites_cname_state_113_check CHECK (
        cname_state IS NULL OR cname_state IN ('pending','failed','done')
    ),
    ADD CONSTRAINT sites_cname_revision_113_check CHECK (
        (cname_current_revision IS NULL AND cname_lkg_revision IS NULL) OR
        (cname_current_revision > 0 AND
         (cname_lkg_revision IS NULL OR cname_lkg_revision > 0))
    ),
    ADD CONSTRAINT sites_cname_authority_113_check CHECK (
        (cname_mode IS NULL AND cname_domain IS NULL AND cname_hostname2 IS NULL AND
         cname_state IS NULL AND cname_task_id IS NULL AND
         cname_current_revision IS NULL AND cname_lkg_revision IS NULL) OR
        (cname_mode IS NOT NULL AND cname_domain IS NOT NULL AND cname_hostname2 IS NOT NULL AND
         cname_state IS NOT NULL AND cname_task_id IS NOT NULL AND cname_current_revision IS NOT NULL AND
         (cname_mode='site' OR package_subscription_id IS NOT NULL))
    );

CREATE TABLE cname_allocations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('site','package')),
    site_owner_id uuid,
    package_subscription_id uuid,
    current_claim_id uuid NOT NULL,
    lkg_claim_id uuid,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    lkg_revision bigint CHECK (lkg_revision IS NULL OR (lkg_revision > 0 AND lkg_revision <= current_revision)),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN ('pending','failed','done')),
    job_id uuid NOT NULL,
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    UNIQUE (tenant_scope_id,id),
    UNIQUE (tenant_id,id),
    FOREIGN KEY (tenant_scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,job_id)
        REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_scope_id,site_owner_id,owner_user_id)
        REFERENCES sites(scope_id,id,owner_user_id) ON DELETE RESTRICT,
    FOREIGN KEY (package_subscription_id,tenant_scope_id,owner_user_id)
        REFERENCES package_monitor_subscription_owners(subscription_id,tenant_scope_id,owner_user_id)
        ON DELETE RESTRICT,
    CHECK (
        (mode='site' AND site_owner_id IS NOT NULL AND package_subscription_id IS NULL) OR
        (mode='package' AND site_owner_id IS NULL AND package_subscription_id IS NOT NULL)
    ),
    CHECK (
        (state='failed' AND failure_code IS NOT NULL) OR
        (state IN ('pending','done') AND failure_code IS NULL)
    ),
    CHECK ((lkg_claim_id IS NULL) = (lkg_revision IS NULL))
);

CREATE UNIQUE INDEX cname_allocations_site_owner_113_uidx
    ON cname_allocations (tenant_scope_id,site_owner_id) WHERE mode='site';
CREATE UNIQUE INDEX cname_allocations_package_owner_113_uidx
    ON cname_allocations (tenant_scope_id,package_subscription_id) WHERE mode='package';

CREATE TABLE cname_hostname_claims (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    provider_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    domain text NOT NULL CHECK (
        domain=lower(btrim(domain)) AND char_length(domain) BETWEEN 1 AND 253
    ),
    hostname text NOT NULL CHECK (
        hostname=lower(btrim(hostname)) AND char_length(hostname) BETWEEN 1 AND 253
    ),
    explicit_hostname boolean NOT NULL,
    hmac_key_id text CHECK (
        hmac_key_id IS NULL OR hmac_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (id,allocation_id),
    UNIQUE (allocation_id,generation),
    FOREIGN KEY (tenant_scope_id,allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_scope_id,provider_id)
        REFERENCES dns_providers(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,zone_id,provider_id,domain)
        REFERENCES dns_zones(scope_id,id,provider_id,name) ON DELETE RESTRICT,
    CHECK (
        (explicit_hostname AND hmac_key_id IS NULL) OR
        (NOT explicit_hostname AND hmac_key_id IS NOT NULL)
    ),
    CHECK (
        char_length(hostname) > char_length(domain) AND
        right(hostname,char_length(domain)+1)='.'||domain
    )
);

CREATE UNIQUE INDEX cname_hostname_claims_hostname_113_uidx
    ON cname_hostname_claims (lower(hostname));

ALTER TABLE cname_allocations
    ADD CONSTRAINT cname_allocations_current_claim_113_fk
        FOREIGN KEY (current_claim_id,id)
        REFERENCES cname_hostname_claims(id,allocation_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT cname_allocations_lkg_claim_113_fk
        FOREIGN KEY (lkg_claim_id,id)
        REFERENCES cname_hostname_claims(id,allocation_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE cname_site_bindings (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    current_allocation_id uuid NOT NULL,
    lkg_allocation_id uuid,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (tenant_scope_id,site_id),
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,current_allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,lkg_allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE INDEX cname_site_bindings_current_113_idx
    ON cname_site_bindings (tenant_scope_id,current_allocation_id,site_id);

CREATE TABLE cname_allocation_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    site_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('allocate','regenerate','rebind','settle','bind')),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND request_id=btrim(request_id) AND
        request_id !~ '[[:cntrl:]]'
    ),
    job_id uuid NOT NULL,
    hmac_key_id text CHECK (
        hmac_key_id IS NULL OR hmac_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    generation bigint NOT NULL CHECK (generation > 0),
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    result_lkg_revision bigint CHECK (
        result_lkg_revision IS NULL OR
        (result_lkg_revision > 0 AND result_lkg_revision <= result_revision)
    ),
    result_state text NOT NULL CHECK (result_state IN ('pending','failed','done')),
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    audit_event_id uuid NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (actor_scope_id,actor_user_id,idempotency_key),
    UNIQUE (tenant_id,job_id,generation,operation,site_id),
    FOREIGN KEY (tenant_scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,job_id)
        REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    CHECK (actor_scope_id=tenant_scope_id),
    CHECK (
        (operation='allocate' AND expected_revision=0 AND result_revision=1) OR
        (operation='bind' AND expected_revision > 0 AND result_revision=expected_revision) OR
        (operation NOT IN ('allocate','bind') AND
         expected_revision > 0 AND result_revision=expected_revision+1)
    ),
    CHECK (
        (result_state='failed' AND failure_code IS NOT NULL) OR
        (result_state IN ('pending','done') AND failure_code IS NULL)
    )
);

CREATE INDEX cname_allocation_requests_allocation_113_idx
    ON cname_allocation_requests (tenant_scope_id,allocation_id,result_revision DESC,created_at DESC);

CREATE FUNCTION validate_cname_allocation_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    reused_claim_explicit boolean;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'CNAME allocations are durable authority facts' USING ERRCODE='P1131';
    END IF;

    IF TG_OP='INSERT' THEN
        IF NEW.current_revision <> 1 OR NEW.generation <> 1 OR NEW.state <> 'pending' OR
           NEW.lkg_claim_id IS NOT NULL OR NEW.lkg_revision IS NOT NULL OR
           NEW.failure_code IS NOT NULL OR NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'CNAME allocation must start as revision one pending without LKG'
                USING ERRCODE='P1131';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id,NEW.tenant_id,NEW.tenant_scope_id,NEW.owner_user_id,NEW.mode,
           NEW.site_owner_id,NEW.package_subscription_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.tenant_scope_id,OLD.owner_user_id,OLD.mode,
           OLD.site_owner_id,OLD.package_subscription_id,OLD.created_at) OR
       NEW.current_revision <> OLD.current_revision+1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'CNAME allocation identity or CAS revision is invalid' USING ERRCODE='P1131';
    END IF;

    IF NEW.generation=OLD.generation THEN
        IF OLD.state <> 'pending' OR NEW.state NOT IN ('done','failed') OR
           NEW.current_claim_id IS DISTINCT FROM OLD.current_claim_id OR
           NEW.job_id IS DISTINCT FROM OLD.job_id THEN
            RAISE EXCEPTION 'CNAME allocation settlement is not an exact pending replay'
                USING ERRCODE='P1131';
        END IF;
        IF NEW.state='done' AND
           (NEW.lkg_claim_id IS DISTINCT FROM NEW.current_claim_id OR
            NEW.lkg_revision IS DISTINCT FROM NEW.current_revision) THEN
            RAISE EXCEPTION 'successful CNAME allocation must promote the current claim to LKG'
                USING ERRCODE='P1131';
        ELSIF NEW.state='failed' AND
              ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
              ROW(OLD.lkg_claim_id,OLD.lkg_revision) THEN
            RAISE EXCEPTION 'failed CNAME allocation must preserve the prior LKG'
                USING ERRCODE='P1131';
        END IF;
    ELSIF NEW.generation=OLD.generation+1 THEN
        IF NEW.current_claim_id IS NOT DISTINCT FROM OLD.current_claim_id THEN
            SELECT explicit_hostname INTO reused_claim_explicit
            FROM cname_hostname_claims
            WHERE id=NEW.current_claim_id AND allocation_id=NEW.id;
            IF reused_claim_explicit IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'only an immutable explicit CNAME claim may be reused across generations'
                    USING ERRCODE='P1131';
            END IF;
        END IF;
        IF NEW.state <> 'pending' OR NEW.job_id IS NOT DISTINCT FROM OLD.job_id OR
           (OLD.state='done' AND
            ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
            ROW(OLD.current_claim_id,OLD.current_revision)) OR
           (OLD.state<>'done' AND
            ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
            ROW(OLD.lkg_claim_id,OLD.lkg_revision)) THEN
            RAISE EXCEPTION 'CNAME regeneration must create a new pending claim and preserve LKG'
                USING ERRCODE='P1131';
        END IF;
    ELSE
        RAISE EXCEPTION 'CNAME allocation generation must remain or advance by one'
            USING ERRCODE='P1131';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cname_allocations_validate_113
BEFORE INSERT OR UPDATE OR DELETE ON cname_allocations
FOR EACH ROW EXECUTE FUNCTION validate_cname_allocation_113();

CREATE FUNCTION assert_cname_allocation_consistency_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_claim cname_hostname_claims%ROWTYPE;
    lkg_claim cname_hostname_claims%ROWTYPE;
    job_row background_jobs%ROWTYPE;
BEGIN
    SELECT * INTO current_claim FROM cname_hostname_claims
    WHERE id=NEW.current_claim_id AND allocation_id=NEW.id;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF current_claim.id IS NULL OR current_claim.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR
       job_row.id IS NULL OR job_row.kind IS DISTINCT FROM 'dns.cname.allocation' THEN
        RAISE EXCEPTION 'CNAME allocation claim or job identity is invalid' USING ERRCODE='P1131';
    END IF;
    IF current_claim.explicit_hostname THEN
        IF current_claim.generation > NEW.generation THEN
            RAISE EXCEPTION 'explicit CNAME claim generation is ahead of its allocation'
                USING ERRCODE='P1131';
        END IF;
    ELSE
        IF current_claim.generation IS DISTINCT FROM NEW.generation THEN
            RAISE EXCEPTION 'generated CNAME claim must be new for the allocation generation'
                USING ERRCODE='P1131';
        END IF;
        IF EXISTS (
            SELECT 1 FROM cname_hostname_claims AS prior_claim
            WHERE prior_claim.allocation_id=NEW.id
              AND prior_claim.generation<NEW.generation
              AND NOT prior_claim.explicit_hostname
              AND prior_claim.hmac_key_id IS NOT DISTINCT FROM current_claim.hmac_key_id
        ) THEN
            RAISE EXCEPTION 'generated CNAME regeneration must rotate its HMAC key'
                USING ERRCODE='P1131';
        END IF;
    END IF;
    IF NEW.lkg_claim_id IS NOT NULL THEN
        SELECT * INTO lkg_claim FROM cname_hostname_claims
        WHERE id=NEW.lkg_claim_id AND allocation_id=NEW.id;
        IF lkg_claim.id IS NULL OR lkg_claim.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR
           lkg_claim.generation > NEW.generation THEN
            RAISE EXCEPTION 'CNAME allocation LKG claim is invalid' USING ERRCODE='P1131';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cname_allocations_consistent_113
AFTER INSERT OR UPDATE ON cname_allocations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_cname_allocation_consistency_113();

CREATE FUNCTION protect_cname_hostname_claim_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'CNAME hostname claims are append-only' USING ERRCODE='P1132';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cname_hostname_claims_append_only_113
BEFORE UPDATE OR DELETE ON cname_hostname_claims
FOR EACH ROW EXECUTE FUNCTION protect_cname_hostname_claim_113();
CREATE TRIGGER cname_hostname_claims_no_truncate_113
BEFORE TRUNCATE ON cname_hostname_claims
FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_hostname_claim_113();

CREATE FUNCTION validate_cname_site_binding_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    site_row sites%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    lkg_row cname_allocations%ROWTYPE;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'CNAME site bindings are durable authority facts' USING ERRCODE='P1133';
    END IF;
    IF TG_OP='INSERT' AND
       (NEW.binding_revision <> 1 OR NEW.updated_at IS DISTINCT FROM NEW.created_at) THEN
        RAISE EXCEPTION 'CNAME site binding must start at revision one' USING ERRCODE='P1133';
    ELSIF TG_OP='UPDATE' AND
          (ROW(NEW.tenant_scope_id,NEW.site_id,NEW.created_at) IS DISTINCT FROM
           ROW(OLD.tenant_scope_id,OLD.site_id,OLD.created_at) OR
           NEW.binding_revision <> OLD.binding_revision+1 OR NEW.updated_at < OLD.updated_at) THEN
        RAISE EXCEPTION 'CNAME site binding CAS revision is invalid' USING ERRCODE='P1133';
    END IF;

    SELECT * INTO site_row FROM sites
    WHERE scope_id=NEW.tenant_scope_id AND id=NEW.site_id;
    SELECT * INTO allocation_row FROM cname_allocations
    WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.current_allocation_id;
    IF site_row.id IS NULL OR allocation_row.id IS NULL OR
       allocation_row.owner_user_id IS DISTINCT FROM site_row.owner_user_id OR
       (allocation_row.mode='site' AND allocation_row.site_owner_id IS DISTINCT FROM site_row.id) OR
       (allocation_row.mode='package' AND
        allocation_row.package_subscription_id IS DISTINCT FROM site_row.package_subscription_id) THEN
        RAISE EXCEPTION 'CNAME site binding does not match its authoritative mode owner'
            USING ERRCODE='P1133';
    END IF;

    IF NEW.lkg_allocation_id IS NOT NULL THEN
        SELECT * INTO lkg_row FROM cname_allocations
        WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.lkg_allocation_id;
        IF lkg_row.id IS NULL OR lkg_row.owner_user_id IS DISTINCT FROM site_row.owner_user_id OR
           lkg_row.lkg_claim_id IS NULL OR lkg_row.lkg_revision IS NULL THEN
            RAISE EXCEPTION 'CNAME site binding LKG owner is invalid' USING ERRCODE='P1133';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cname_site_bindings_validate_113
BEFORE INSERT OR UPDATE OR DELETE ON cname_site_bindings
FOR EACH ROW EXECUTE FUNCTION validate_cname_site_binding_113();

CREATE FUNCTION validate_sites_cname_authority_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding_row cname_site_bindings%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    lkg_allocation_row cname_allocations%ROWTYPE;
    lkg_claim_row cname_hostname_claims%ROWTYPE;
    zone_default boolean;
BEGIN
    IF NEW.cname_mode IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO binding_row FROM cname_site_bindings
    WHERE tenant_scope_id=NEW.scope_id AND site_id=NEW.id;
    SELECT * INTO allocation_row FROM cname_allocations
    WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.current_allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims
    WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT is_default INTO zone_default FROM dns_zones
    WHERE scope_id=claim_row.tenant_scope_id AND id=claim_row.zone_id;

    IF binding_row.site_id IS NULL OR allocation_row.id IS NULL OR claim_row.id IS NULL OR
       allocation_row.mode IS DISTINCT FROM NEW.cname_mode OR
       allocation_row.state IS DISTINCT FROM NEW.cname_state OR
       allocation_row.job_id IS DISTINCT FROM NEW.cname_task_id OR
       allocation_row.current_revision IS DISTINCT FROM NEW.cname_current_revision OR
       (NEW.cname_domain<>'' AND NEW.cname_domain IS DISTINCT FROM claim_row.domain) OR
       (NEW.cname_domain='' AND zone_default IS DISTINCT FROM true) OR
       (NEW.cname_hostname2='' AND claim_row.explicit_hostname) OR
       (NEW.cname_hostname2<>'' AND
        (NOT claim_row.explicit_hostname OR NEW.cname_hostname2 IS DISTINCT FROM claim_row.hostname)) THEN
        RAISE EXCEPTION 'site CNAME projection does not match durable allocation authority'
            USING ERRCODE='P1134';
    END IF;

    IF binding_row.lkg_allocation_id IS NULL THEN
        IF NEW.cname_lkg_revision IS NOT NULL OR NEW.cname<>'' THEN
            RAISE EXCEPTION 'site CNAME without an LKG allocation must keep an empty legacy projection'
                USING ERRCODE='P1134';
        END IF;
    ELSE
        SELECT * INTO lkg_allocation_row FROM cname_allocations
        WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.lkg_allocation_id;
        SELECT * INTO lkg_claim_row FROM cname_hostname_claims
        WHERE id=lkg_allocation_row.lkg_claim_id AND allocation_id=lkg_allocation_row.id;
        IF lkg_allocation_row.id IS NULL OR lkg_claim_row.id IS NULL OR
           lkg_allocation_row.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
           lkg_allocation_row.lkg_revision IS DISTINCT FROM NEW.cname_lkg_revision OR
           lkg_claim_row.hostname IS DISTINCT FROM NEW.cname THEN
            RAISE EXCEPTION 'site CNAME LKG projection does not match its bound durable claim'
                USING ERRCODE='P1134';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER sites_cname_authority_validate_113
AFTER INSERT OR UPDATE OF package_subscription_id,cname_mode,cname_domain,cname_hostname2,
    cname_state,cname_task_id,cname_current_revision,cname_lkg_revision ON sites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_sites_cname_authority_113();

CREATE FUNCTION protect_cname_allocation_request_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'CNAME allocation requests are append-only' USING ERRCODE='P1135';
    RETURN OLD;
END;
$$;

CREATE TRIGGER cname_allocation_requests_append_only_113
BEFORE UPDATE OR DELETE ON cname_allocation_requests
FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_request_113();
CREATE TRIGGER cname_allocation_requests_no_truncate_113
BEFORE TRUNCATE ON cname_allocation_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_request_113();

CREATE FUNCTION validate_cname_allocation_request_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    audit_row audit_events%ROWTYPE;
    job_row background_jobs%ROWTYPE;
    binding_row cname_site_bindings%ROWTYPE;
BEGIN
    SELECT * INTO allocation_row FROM cname_allocations
    WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims
    WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    SELECT * INTO binding_row FROM cname_site_bindings
    WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id;

    IF allocation_row.id IS NULL OR claim_row.id IS NULL OR audit_row.id IS NULL OR job_row.id IS NULL OR
       binding_row.current_allocation_id IS DISTINCT FROM NEW.allocation_id OR
       allocation_row.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       allocation_row.job_id IS DISTINCT FROM NEW.job_id OR
       allocation_row.generation IS DISTINCT FROM NEW.generation OR
       allocation_row.current_revision IS DISTINCT FROM NEW.result_revision OR
       allocation_row.lkg_revision IS DISTINCT FROM NEW.result_lkg_revision OR
       allocation_row.state IS DISTINCT FROM NEW.result_state OR
       allocation_row.failure_code IS DISTINCT FROM NEW.failure_code OR
       claim_row.hmac_key_id IS DISTINCT FROM NEW.hmac_key_id OR
       (NEW.operation='bind' AND allocation_row.mode<>'package') OR
       job_row.kind IS DISTINCT FROM 'dns.cname.allocation' OR
       audit_row.scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'dns.cname.'||NEW.operation OR
       audit_row.resource_type IS DISTINCT FROM 'cname_allocation' OR
       audit_row.resource_id IS DISTINCT FROM NEW.allocation_id::text OR
       audit_row.request_id IS DISTINCT FROM NEW.request_id OR
       audit_row.result IS DISTINCT FROM
           (CASE WHEN NEW.result_state='failed' THEN 'failure' ELSE 'success' END) OR
       audit_row.occurred_at < NEW.created_at THEN
        RAISE EXCEPTION 'CNAME allocation request lacks exact job, actor, audit, or result authority'
            USING ERRCODE='P1135';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cname_allocation_requests_validate_113
AFTER INSERT ON cname_allocation_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cname_allocation_request_113();
