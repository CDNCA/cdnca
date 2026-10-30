LOCK TABLE schema_migrations,package_subscriptions,package_cycle_enforcement_heads,
    package_cycle_enforcement_transitions,package_cycle_usage_adjustments,sites,
    background_jobs,access_scopes,tenants IN ACCESS EXCLUSIVE MODE;

DO $migration_164$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>163 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>163 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=163 AND migration_id='163_account_registration_challenge' AND
              checksum_sha256='a3fb276eb890cfcb8e526c3b1b7539d5b970d35c4e465422184308e0d0c9d799' AND
              down_checksum_sha256='b3dfc2d6f8b8e04dc41e9d7b04349306d9345f5fcb7d1d1156e3a7f15f075dc8' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('package_period_reset_claims_164') IS NOT NULL OR
         to_regclass('package_period_reset_facts_164') IS NOT NULL OR
         to_regclass('package_period_reset_recovery_outbox_164') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 164 requires a contiguous verified 163 release head'
            USING ERRCODE='P1640';
    END IF;
END;
$migration_164$;

CREATE TABLE package_period_reset_claims_164 (
    claim_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL,
    target_reset_key text NOT NULL CHECK(
        target_reset_key=btrim(target_reset_key) AND char_length(target_reset_key) BETWEEN 1 AND 256
    ),
    target_cycle_starts_at timestamptz NOT NULL CHECK(isfinite(target_cycle_starts_at)),
    target_cycle_ends_at timestamptz NOT NULL CHECK(
        isfinite(target_cycle_ends_at) AND target_cycle_ends_at>target_cycle_starts_at
    ),
    timezone text NOT NULL CHECK(is_valid_package_subscription_timezone(timezone)),
    evaluated_at timestamptz NOT NULL CHECK(isfinite(evaluated_at)),
    source_subscription_revision bigint NOT NULL CHECK(source_subscription_revision>0),
    source_enforcement_revision bigint NOT NULL CHECK(source_enforcement_revision>0),
    source_period_key text NOT NULL CHECK(
        source_period_key=btrim(source_period_key) AND char_length(source_period_key) BETWEEN 1 AND 256
    ),
    request_id text NOT NULL CHECK(
        request_id=btrim(request_id) AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    state text NOT NULL CHECK(state IN ('claimed','completed')),
    worker_id text NOT NULL CHECK(
        worker_id=btrim(worker_id) AND worker_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    lease_id uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL CHECK(isfinite(lease_expires_at)),
    response_body jsonb CHECK(response_body IS NULL OR jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    completed_at timestamptz CHECK(completed_at IS NULL OR isfinite(completed_at)),
    UNIQUE(tenant_scope_id,subscription_id,target_reset_key),
    FOREIGN KEY(tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,subscription_id)
        REFERENCES package_cycle_enforcement_heads(tenant_scope_id,subscription_id) ON DELETE RESTRICT,
    CHECK(target_cycle_starts_at<=evaluated_at AND evaluated_at<target_cycle_ends_at),
    CHECK(lease_expires_at>created_at),
    CHECK(
        (state='claimed' AND response_body IS NULL AND completed_at IS NULL) OR
        (state='completed' AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX package_period_reset_claims_164_due_idx
    ON package_period_reset_claims_164(state,lease_expires_at,created_at,claim_id)
    WHERE state='claimed';

CREATE TABLE package_period_reset_facts_164 (
    reset_id uuid PRIMARY KEY,
    claim_id uuid NOT NULL UNIQUE REFERENCES package_period_reset_claims_164(claim_id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    prior_period_key text NOT NULL CHECK(
        prior_period_key=btrim(prior_period_key) AND char_length(prior_period_key) BETWEEN 1 AND 256
    ),
    prior_cycle_starts_at timestamptz NOT NULL CHECK(isfinite(prior_cycle_starts_at)),
    prior_cycle_ends_at timestamptz NOT NULL CHECK(
        isfinite(prior_cycle_ends_at) AND prior_cycle_ends_at>prior_cycle_starts_at
    ),
    prior_status text NOT NULL CHECK(prior_status IN ('active','suspended')),
    prior_reason_code text CHECK(prior_reason_code IS NULL OR prior_reason_code IN (
        'traffic_exceeded','bandwidth_exceeded','connections_exceeded','sites_exceeded','manual_override'
    )),
    prior_enforcement_revision bigint NOT NULL CHECK(prior_enforcement_revision>0),
    prior_evidence_digest bytea NOT NULL CHECK(octet_length(prior_evidence_digest)=32),
    prior_decision_digest bytea NOT NULL CHECK(octet_length(prior_decision_digest)=32),
    prior_adjustment_count integer NOT NULL CHECK(prior_adjustment_count>=0),
    new_period_key text NOT NULL CHECK(
        new_period_key=btrim(new_period_key) AND char_length(new_period_key) BETWEEN 1 AND 256
    ),
    new_cycle_starts_at timestamptz NOT NULL CHECK(isfinite(new_cycle_starts_at)),
    new_cycle_ends_at timestamptz NOT NULL CHECK(
        isfinite(new_cycle_ends_at) AND new_cycle_ends_at>new_cycle_starts_at
    ),
    timezone text NOT NULL CHECK(is_valid_package_subscription_timezone(timezone)),
    new_status text NOT NULL CHECK(new_status IN ('active','suspended')),
    new_reason_code text CHECK(new_reason_code IS NULL OR new_reason_code IN (
        'traffic_exceeded','bandwidth_exceeded','connections_exceeded','sites_exceeded','manual_override'
    )),
    new_enforcement_revision bigint NOT NULL CHECK(new_enforcement_revision=prior_enforcement_revision+1),
    new_evidence_digest bytea NOT NULL CHECK(octet_length(new_evidence_digest)=32),
    new_decision_digest bytea NOT NULL CHECK(octet_length(new_decision_digest)=32),
    recovery_authorized boolean NOT NULL,
    recovery_job_count integer NOT NULL CHECK(recovery_job_count>=0),
    request_id text NOT NULL CHECK(
        request_id=btrim(request_id) AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    UNIQUE(tenant_scope_id,subscription_id,new_period_key),
    FOREIGN KEY(tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,subscription_id)
        REFERENCES package_cycle_enforcement_heads(tenant_scope_id,subscription_id) ON DELETE RESTRICT,
    CHECK(new_cycle_starts_at>=prior_cycle_ends_at),
    CHECK(new_period_key<>prior_period_key),
    CHECK(recovery_authorized OR recovery_job_count=0),
    CHECK(
        (prior_status='active' AND prior_reason_code IS NULL OR prior_reason_code='manual_override') OR
        (prior_status='suspended' AND prior_reason_code IS NOT NULL)
    ),
    CHECK(
        (new_status='active' AND new_reason_code IS NULL OR new_reason_code='manual_override') OR
        (new_status='suspended' AND new_reason_code IS NOT NULL)
    )
);

CREATE TABLE package_period_reset_recovery_outbox_164 (
    reset_id uuid NOT NULL REFERENCES package_period_reset_facts_164(reset_id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    job_id uuid NOT NULL UNIQUE REFERENCES background_jobs(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK(
        request_id=btrim(request_id) AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(reset_id,site_id),
    FOREIGN KEY(tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE FUNCTION package_period_reset_claim_single_winner_164(
    requested_claim_id uuid,
    requested_worker_id text,
    requested_lease_id uuid,
    requested_now timestamptz,
    requested_lease interval,
    expected_request_digest bytea,
    expected_subscription_revision bigint,
    expected_enforcement_revision bigint
)
RETURNS SETOF package_period_reset_claims_164
LANGUAGE plpgsql AS $$
BEGIN
    IF requested_claim_id IS NULL OR requested_lease_id IS NULL OR requested_now IS NULL OR
       requested_worker_id IS NULL OR requested_worker_id<>btrim(requested_worker_id) OR
       requested_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR
       requested_lease<interval '1 second' OR requested_lease>interval '1 hour' OR
       octet_length(expected_request_digest)<>32 OR expected_subscription_revision<1 OR
       expected_enforcement_revision<1 THEN
        RAISE EXCEPTION 'invalid package period reset claim request' USING ERRCODE='P1641';
    END IF;
    RETURN QUERY
    UPDATE package_period_reset_claims_164 claim
    SET worker_id=requested_worker_id,lease_id=requested_lease_id,
        lease_expires_at=requested_now+requested_lease
    WHERE claim.claim_id=requested_claim_id AND claim.state='claimed' AND
          claim.lease_expires_at<=requested_now AND claim.request_digest=expected_request_digest AND
          claim.source_subscription_revision=expected_subscription_revision AND
          claim.source_enforcement_revision=expected_enforcement_revision
    RETURNING claim.*;
END;
$$;

CREATE FUNCTION guard_package_period_reset_claim_164()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'package period reset claims cannot be deleted' USING ERRCODE='P1642';
    END IF;
    IF ROW(NEW.claim_id,NEW.tenant_scope_id,NEW.tenant_id,NEW.subscription_id,NEW.target_reset_key,
           NEW.target_cycle_starts_at,NEW.target_cycle_ends_at,NEW.timezone,NEW.evaluated_at,
           NEW.source_subscription_revision,NEW.source_enforcement_revision,NEW.source_period_key,
           NEW.request_id,NEW.request_digest,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.claim_id,OLD.tenant_scope_id,OLD.tenant_id,OLD.subscription_id,OLD.target_reset_key,
           OLD.target_cycle_starts_at,OLD.target_cycle_ends_at,OLD.timezone,OLD.evaluated_at,
           OLD.source_subscription_revision,OLD.source_enforcement_revision,OLD.source_period_key,
           OLD.request_id,OLD.request_digest,OLD.created_at) OR OLD.state='completed' THEN
        RAISE EXCEPTION 'package period reset claim mutation rejected' USING ERRCODE='P1642';
    END IF;
    IF NEW.state='claimed' THEN
        IF OLD.state<>'claimed' OR NEW.lease_expires_at<=OLD.lease_expires_at THEN
            RAISE EXCEPTION 'package period reset claim mutation rejected' USING ERRCODE='P1642';
        END IF;
    ELSIF NEW.state='completed' THEN
        IF OLD.state<>'claimed' OR
           ROW(NEW.worker_id,NEW.lease_id,NEW.lease_expires_at) IS DISTINCT FROM
           ROW(OLD.worker_id,OLD.lease_id,OLD.lease_expires_at) THEN
            RAISE EXCEPTION 'package period reset claim mutation rejected' USING ERRCODE='P1642';
        END IF;
    ELSE
        RAISE EXCEPTION 'package period reset claim mutation rejected' USING ERRCODE='P1642';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_package_period_reset_fact_mutation_164()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'package period reset facts are immutable' USING ERRCODE='P1643';
END;
$$;

CREATE TRIGGER package_period_reset_claim_guard_164
BEFORE UPDATE OR DELETE ON package_period_reset_claims_164
FOR EACH ROW EXECUTE FUNCTION guard_package_period_reset_claim_164();
CREATE TRIGGER package_period_reset_claim_no_truncate_164
BEFORE TRUNCATE ON package_period_reset_claims_164
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_period_reset_fact_mutation_164();
CREATE TRIGGER package_period_reset_fact_immutable_164
BEFORE UPDATE OR DELETE ON package_period_reset_facts_164
FOR EACH ROW EXECUTE FUNCTION prevent_package_period_reset_fact_mutation_164();
CREATE TRIGGER package_period_reset_fact_no_truncate_164
BEFORE TRUNCATE ON package_period_reset_facts_164
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_period_reset_fact_mutation_164();
CREATE TRIGGER package_period_reset_outbox_immutable_164
BEFORE UPDATE OR DELETE ON package_period_reset_recovery_outbox_164
FOR EACH ROW EXECUTE FUNCTION prevent_package_period_reset_fact_mutation_164();
CREATE TRIGGER package_period_reset_outbox_no_truncate_164
BEFORE TRUNCATE ON package_period_reset_recovery_outbox_164
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_period_reset_fact_mutation_164();

REVOKE ALL ON package_period_reset_claims_164,package_period_reset_facts_164,
    package_period_reset_recovery_outbox_164 FROM PUBLIC;
REVOKE ALL ON FUNCTION package_period_reset_claim_single_winner_164(
    uuid,text,uuid,timestamptz,interval,bytea,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_package_period_reset_claim_164() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_package_period_reset_fact_mutation_164() FROM PUBLIC;
