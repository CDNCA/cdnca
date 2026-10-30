LOCK TABLE schema_migrations, package_subscriptions, access_scopes, users IN ACCESS EXCLUSIVE MODE;

DO $migration_146$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 145 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 145 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 145 AND migration_id = '145_plugin_installations' AND
              checksum_sha256 = 'c2a8d53baacfd5cf0d0229e70b1cb90238cfedf08b08ccc2118a071d569cf163' AND
              down_checksum_sha256 = 'f0c80ef2c4fda3e6d7e5812723232959b4864c90331b6c037fc00e9b27343f88' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('package_cycle_enforcement_heads') IS NOT NULL OR
         to_regclass('package_cycle_enforcement_claims') IS NOT NULL OR
         to_regclass('package_cycle_enforcement_transitions') IS NOT NULL OR
         to_regclass('package_cycle_enforcement_overrides') IS NOT NULL OR
         to_regclass('package_cycle_usage_adjustments') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 146 requires the exact verified 145 release head'
            USING ERRCODE = 'P1460';
    END IF;
END;
$migration_146$;

CREATE FUNCTION valid_package_cycle_operations_146(value text[])
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT value = ARRAY[]::text[] OR value = ARRAY['create','expand']::text[];
$$;

CREATE TABLE package_cycle_enforcement_heads (
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    cycle_starts_at timestamptz NOT NULL,
    cycle_ends_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active','suspended','unknown')),
    reason_code text CHECK (reason_code IS NULL OR reason_code IN (
        'traffic_exceeded','bandwidth_exceeded','connections_exceeded','sites_exceeded',
        'manual_override','dependency_unavailable'
    )),
    blocked_operations text[] NOT NULL CHECK (valid_package_cycle_operations_146(blocked_operations)),
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    evidence_id text NOT NULL CHECK (evidence_id = btrim(evidence_id) AND char_length(evidence_id) BETWEEN 1 AND 256),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest) = 32),
    lkg_status text NOT NULL CHECK (lkg_status IN ('active','suspended')),
    lkg_reason_code text CHECK (lkg_reason_code IS NULL OR lkg_reason_code IN (
        'traffic_exceeded','bandwidth_exceeded','connections_exceeded','sites_exceeded','manual_override'
    )),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id,subscription_id),
    UNIQUE (tenant_scope_id,subscription_id,revision),
    UNIQUE (tenant_scope_id,subscription_id,evidence_id),
    FOREIGN KEY (tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK (cycle_ends_at > cycle_starts_at),
    CHECK ((status = 'suspended') = (blocked_operations = ARRAY['create','expand']::text[])),
    CHECK ((status = 'active' AND reason_code IS NULL OR reason_code = 'manual_override') OR
           (status = 'suspended' AND reason_code IS NOT NULL) OR
           (status = 'unknown' AND reason_code = 'dependency_unavailable')),
    CHECK ((lkg_status = 'active' AND lkg_reason_code IS NULL OR lkg_reason_code = 'manual_override') OR
           (lkg_status = 'suspended' AND lkg_reason_code IS NOT NULL))
);

CREATE TABLE package_cycle_enforcement_claims (
    claim_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    evidence_id text NOT NULL CHECK (evidence_id = btrim(evidence_id) AND char_length(evidence_id) BETWEEN 1 AND 256),
    target_period_key text NOT NULL CHECK (target_period_key = btrim(target_period_key) AND char_length(target_period_key) BETWEEN 1 AND 256),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_body jsonb NOT NULL CHECK (jsonb_typeof(request_body) = 'object'),
    state text NOT NULL CHECK (state IN ('pending','claimed','completed')),
    worker_id text CHECK (worker_id IS NULL OR worker_id = btrim(worker_id) AND char_length(worker_id) BETWEEN 1 AND 128),
    lease_expires_at timestamptz,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_scope_id, subscription_id, evidence_id),
    FOREIGN KEY (tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK (
        (state = 'pending' AND worker_id IS NULL AND lease_expires_at IS NULL AND response_body IS NULL AND completed_at IS NULL) OR
        (state = 'claimed' AND worker_id IS NOT NULL AND lease_expires_at > created_at AND response_body IS NULL AND completed_at IS NULL) OR
        (state = 'completed' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX package_cycle_enforcement_claims_runnable_146
    ON package_cycle_enforcement_claims (state,lease_expires_at,created_at,claim_id)
    WHERE state <> 'completed';

CREATE TABLE package_cycle_enforcement_transitions (
    transition_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('active','suspended')),
    reason_code text CHECK (reason_code IS NULL OR reason_code IN (
        'traffic_exceeded','bandwidth_exceeded','connections_exceeded','sites_exceeded','manual_override'
    )),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest) = 32),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,subscription_id,revision),
    FOREIGN KEY (tenant_scope_id,subscription_id)
        REFERENCES package_cycle_enforcement_heads(tenant_scope_id,subscription_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE package_cycle_enforcement_overrides (
    override_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    operation text NOT NULL CHECK (operation IN ('apply','revoke')),
    mode text NOT NULL CHECK (mode IN ('keep_active','force_suspend')),
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    reason text NOT NULL CHECK (reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 512),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,subscription_id,period_key,revision),
    FOREIGN KEY (tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE TABLE package_cycle_usage_adjustments (
    adjustment_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    metric text NOT NULL CHECK (metric IN ('traffic_bytes','bandwidth_bps','connections','sites')),
    kind text NOT NULL CHECK (kind IN ('credit','reversal')),
    amount numeric(20,0) NOT NULL CHECK (amount > 0 AND amount <= 18446744073709551615),
    reverses_adjustment_id uuid REFERENCES package_cycle_usage_adjustments(adjustment_id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (reverses_adjustment_id),
    FOREIGN KEY (tenant_scope_id,subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK ((kind = 'credit' AND reverses_adjustment_id IS NULL) OR
           (kind = 'reversal' AND reverses_adjustment_id IS NOT NULL))
);

CREATE FUNCTION package_cycle_claim_single_winner_146(
    requested_worker text,
    requested_limit integer,
    requested_lease interval
)
RETURNS SETOF package_cycle_enforcement_claims
LANGUAGE plpgsql AS $$
BEGIN
    IF requested_worker IS NULL OR requested_worker <> btrim(requested_worker) OR
       char_length(requested_worker) NOT BETWEEN 1 AND 128 OR
       requested_limit NOT BETWEEN 1 AND 100 OR
       requested_lease < interval '1 second' OR requested_lease > interval '1 hour' THEN
        RAISE EXCEPTION 'invalid package cycle claim request' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    WITH winner AS (
        SELECT claim_id
        FROM package_cycle_enforcement_claims
        WHERE state = 'pending' OR (state = 'claimed' AND lease_expires_at <= clock_timestamp())
        ORDER BY created_at,claim_id
        FOR UPDATE SKIP LOCKED
        LIMIT requested_limit
    )
    UPDATE package_cycle_enforcement_claims AS claim
    SET state = 'claimed', worker_id = requested_worker,
        lease_expires_at = clock_timestamp() + requested_lease
    FROM winner
    WHERE claim.claim_id = winner.claim_id
    RETURNING claim.*;
END;
$$;

CREATE FUNCTION protect_package_cycle_fact_146()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'package cycle enforcement facts are append-only';
END;
$$;

CREATE TRIGGER package_cycle_transitions_append_only_146
BEFORE UPDATE OR DELETE ON package_cycle_enforcement_transitions
FOR EACH ROW EXECUTE FUNCTION protect_package_cycle_fact_146();
CREATE TRIGGER package_cycle_overrides_append_only_146
BEFORE UPDATE OR DELETE ON package_cycle_enforcement_overrides
FOR EACH ROW EXECUTE FUNCTION protect_package_cycle_fact_146();
CREATE TRIGGER package_cycle_adjustments_append_only_146
BEFORE UPDATE OR DELETE ON package_cycle_usage_adjustments
FOR EACH ROW EXECUTE FUNCTION protect_package_cycle_fact_146();

CREATE FUNCTION prevent_package_cycle_truncate_146()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'package cycle enforcement tables cannot be truncated';
END;
$$;

CREATE TRIGGER package_cycle_heads_no_truncate_146 BEFORE TRUNCATE ON package_cycle_enforcement_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_cycle_truncate_146();
CREATE TRIGGER package_cycle_claims_no_truncate_146 BEFORE TRUNCATE ON package_cycle_enforcement_claims
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_cycle_truncate_146();
CREATE TRIGGER package_cycle_transitions_no_truncate_146 BEFORE TRUNCATE ON package_cycle_enforcement_transitions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_cycle_truncate_146();
CREATE TRIGGER package_cycle_overrides_no_truncate_146 BEFORE TRUNCATE ON package_cycle_enforcement_overrides
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_cycle_truncate_146();
CREATE TRIGGER package_cycle_adjustments_no_truncate_146 BEFORE TRUNCATE ON package_cycle_usage_adjustments
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_cycle_truncate_146();

REVOKE ALL ON package_cycle_enforcement_heads, package_cycle_enforcement_claims,
    package_cycle_enforcement_transitions, package_cycle_enforcement_overrides,
    package_cycle_usage_adjustments FROM PUBLIC;
REVOKE ALL ON FUNCTION valid_package_cycle_operations_146(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_cycle_claim_single_winner_146(text,integer,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_cycle_fact_146() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_package_cycle_truncate_146() FROM PUBLIC;
