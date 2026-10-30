LOCK TABLE schema_migrations,cname_allocations,cname_allocation_requests,cname_site_bindings,
    cname_hostname_claims,sites,package_subscriptions,node_line_groups,
    node_line_group_revisions,node_line_endpoints,dns_zones,dns_providers,
    background_jobs,access_scopes IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 125 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=125 AND migration_id='125_dns_reconcile_provider_report_fence'
          AND checksum_sha256='7efe10d2f8015fbff6adca362f4a1142b88fea74015652719a35ac68c22fde8e'
          AND down_checksum_sha256='7aa810bf6c5f03ae5cf4750a1f73e8da378f04757dd0693f8c5f26c4ddc88a82'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 126 requires the exact verified 125 release head' USING ERRCODE='P1260';
    END IF;
END;
$$;

ALTER TABLE package_subscriptions
    ADD CONSTRAINT package_subscriptions_scope_id_126_key UNIQUE (tenant_scope_id,id);
ALTER TABLE dns_zones
    ADD CONSTRAINT dns_zones_scope_id_126_key UNIQUE (scope_id,id);

CREATE TABLE cname_allocation_targets (
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    job_id uuid NOT NULL,
    site_id uuid NOT NULL,
    package_subscription_id uuid NOT NULL,
    node_group_id uuid NOT NULL,
    node_group_revision bigint NOT NULL CHECK (node_group_revision > 0),
    provider_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    zone_revision bigint NOT NULL CHECK (zone_revision > 0),
    owner_name text NOT NULL,
    target_a text[] NOT NULL DEFAULT '{}',
    target_aaaa text[] NOT NULL DEFAULT '{}',
    ttl integer NOT NULL CHECK (ttl=300),
    target_digest text NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL,
    site_revision bigint NOT NULL CHECK (site_revision > 0),
    allocation_revision bigint NOT NULL CHECK (allocation_revision > 0),
    child_task_id uuid,
    child_task_revision bigint,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_scope_id,allocation_id,allocation_revision),
	FOREIGN KEY (tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
	FOREIGN KEY (tenant_scope_id,package_subscription_id)
		REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,node_group_id)
        REFERENCES node_line_groups(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,node_group_id,node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id,line_group_id,revision) ON DELETE RESTRICT,
	FOREIGN KEY (tenant_scope_id,zone_id) REFERENCES dns_zones(scope_id,id) ON DELETE RESTRICT,
	FOREIGN KEY (tenant_scope_id,provider_id) REFERENCES dns_providers(scope_id,id) ON DELETE RESTRICT,
    CHECK (cardinality(target_a)+cardinality(target_aaaa)>0),
    CHECK ((child_task_id IS NULL)=(child_task_revision IS NULL))
);

CREATE TABLE cname_allocation_intents (
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    job_id uuid NOT NULL,
    site_id uuid NOT NULL,
    package_subscription_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('site','package')),
    domain text NOT NULL,
    hostname text NOT NULL,
    idempotency_key text NOT NULL,
    request_id text NOT NULL,
    trace_id text NOT NULL,
    expected_site_revision bigint NOT NULL CHECK (expected_site_revision>0),
    regenerate boolean NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,job_id),
	FOREIGN KEY (tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
	FOREIGN KEY (tenant_scope_id,package_subscription_id)
		REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (tenant_scope_id=actor_scope_id)
);

CREATE FUNCTION protect_cname_allocation_target_126() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR TG_OP='TRUNCATE' THEN
        RAISE EXCEPTION 'CNAME target facts are durable' USING ERRCODE='P1261';
    END IF;
    IF TG_OP='UPDATE' AND (
        ROW(NEW.tenant_id,NEW.tenant_scope_id,NEW.allocation_id,NEW.job_id,NEW.site_id,
            NEW.package_subscription_id,NEW.node_group_id,NEW.node_group_revision,
            NEW.provider_id,NEW.zone_id,NEW.zone_revision,NEW.owner_name,NEW.target_a,
            NEW.target_aaaa,NEW.ttl,NEW.target_digest,NEW.actor_user_id,NEW.request_id,
            NEW.site_revision,NEW.allocation_revision,NEW.created_at) IS DISTINCT FROM
        ROW(OLD.tenant_id,OLD.tenant_scope_id,OLD.allocation_id,OLD.job_id,OLD.site_id,
            OLD.package_subscription_id,OLD.node_group_id,OLD.node_group_revision,
            OLD.provider_id,OLD.zone_id,OLD.zone_revision,OLD.owner_name,OLD.target_a,
            OLD.target_aaaa,OLD.ttl,OLD.target_digest,OLD.actor_user_id,OLD.request_id,
            OLD.site_revision,OLD.allocation_revision,OLD.created_at)
        OR OLD.child_task_id IS NOT NULL
        OR NEW.child_task_id IS NULL OR NEW.child_task_revision < 1
    ) THEN
        RAISE EXCEPTION 'CNAME target mutation is not an exact child correlation' USING ERRCODE='P1261';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_cname_allocation_intent_126() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'CNAME intent facts are append-only' USING ERRCODE='P1261';
END;
$$;

CREATE OR REPLACE FUNCTION validate_sites_cname_authority_113()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	intent_match record;
    binding_row cname_site_bindings%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    lkg_allocation_row cname_allocations%ROWTYPE;
    lkg_claim_row cname_hostname_claims%ROWTYPE;
    zone_default boolean;
BEGIN
    IF NEW.cname_mode IS NULL THEN RETURN NULL; END IF;
	SELECT intent.*,job.state AS intent_job_state INTO intent_match FROM cname_allocation_intents intent
    JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
    WHERE intent.tenant_scope_id=NEW.scope_id AND intent.site_id=NEW.id
      AND intent.package_subscription_id=NEW.package_subscription_id
      AND intent.mode=NEW.cname_mode AND intent.domain=NEW.cname_domain
      AND intent.hostname=NEW.cname_hostname2 AND intent.job_id=NEW.cname_task_id
      AND intent.expected_site_revision=NEW.revision AND job.kind='dns.cname.intent'
      AND job.state IN ('queued','running','failed') ORDER BY intent.created_at DESC LIMIT 1;
    IF intent_match.job_id IS NOT NULL THEN
			IF ((intent_match.intent_job_state IN ('queued','running') AND NEW.cname_state<>'pending') OR
			    (intent_match.intent_job_state='failed' AND NEW.cname_state<>'failed')) OR NEW.cname_current_revision IS NULL OR
           (TG_OP='INSERT' AND (NEW.cname<>'' OR NEW.cname_lkg_revision IS NOT NULL)) OR
           (TG_OP='UPDATE' AND (NEW.cname IS DISTINCT FROM OLD.cname OR
                                NEW.cname_lkg_revision IS DISTINCT FROM OLD.cname_lkg_revision)) THEN
            RAISE EXCEPTION 'site CNAME intent projection is invalid' USING ERRCODE='P1264';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO binding_row FROM cname_site_bindings WHERE tenant_scope_id=NEW.scope_id AND site_id=NEW.id;
    SELECT * INTO allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.current_allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT is_default INTO zone_default FROM dns_zones WHERE scope_id=claim_row.tenant_scope_id AND id=claim_row.zone_id;
    IF binding_row.site_id IS NULL OR allocation_row.id IS NULL OR claim_row.id IS NULL OR
       allocation_row.mode IS DISTINCT FROM NEW.cname_mode OR allocation_row.state IS DISTINCT FROM NEW.cname_state OR
       allocation_row.job_id IS DISTINCT FROM NEW.cname_task_id OR
       allocation_row.current_revision IS DISTINCT FROM NEW.cname_current_revision OR
       (NEW.cname_domain<>'' AND NEW.cname_domain IS DISTINCT FROM claim_row.domain) OR
       (NEW.cname_domain='' AND zone_default IS DISTINCT FROM true) OR
       (NEW.cname_hostname2='' AND claim_row.explicit_hostname) OR
       (NEW.cname_hostname2<>'' AND (NOT claim_row.explicit_hostname OR NEW.cname_hostname2 IS DISTINCT FROM claim_row.hostname)) THEN
        RAISE EXCEPTION 'site CNAME projection does not match durable allocation authority' USING ERRCODE='P1134';
    END IF;
    IF binding_row.lkg_allocation_id IS NULL THEN
        IF NEW.cname_lkg_revision IS NOT NULL OR NEW.cname<>'' THEN
            RAISE EXCEPTION 'site CNAME without LKG allocation is invalid' USING ERRCODE='P1134';
        END IF;
    ELSE
        SELECT * INTO lkg_allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.lkg_allocation_id;
        SELECT * INTO lkg_claim_row FROM cname_hostname_claims WHERE id=lkg_allocation_row.lkg_claim_id AND allocation_id=lkg_allocation_row.id;
        IF lkg_allocation_row.id IS NULL OR lkg_claim_row.id IS NULL OR
           lkg_allocation_row.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
           lkg_allocation_row.lkg_revision IS DISTINCT FROM NEW.cname_lkg_revision OR
           lkg_claim_row.hostname IS DISTINCT FROM NEW.cname THEN
            RAISE EXCEPTION 'site CNAME LKG projection does not match durable claim' USING ERRCODE='P1134';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER cname_allocation_targets_protect_126
BEFORE UPDATE OR DELETE ON cname_allocation_targets
FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_target_126();

CREATE TRIGGER cname_allocation_targets_no_truncate_126
BEFORE TRUNCATE ON cname_allocation_targets
FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_target_126();

CREATE TRIGGER cname_allocation_intents_no_delete_126
BEFORE UPDATE OR DELETE ON cname_allocation_intents
FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_intent_126();

CREATE TRIGGER cname_allocation_intents_no_truncate_126
BEFORE TRUNCATE ON cname_allocation_intents
FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_intent_126();

-- The allocating transaction resolves package_subscriptions.product_snapshot.spec.node_group_id,
-- requires an exact same-scope node_line_groups row and its sealed current node_line_group_revisions.sealed_at,
-- then freezes canonical enabled node_line_endpoints addresses in this table.
