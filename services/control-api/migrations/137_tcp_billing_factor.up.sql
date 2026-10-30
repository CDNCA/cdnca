LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_137$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 136 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 136 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 136 AND migration_id = '136_site_protocol_batch' AND
              checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb' AND
              down_checksum_sha256 = 'dd787a88f25e0594a9daa8a687224ce464fa67d0b91c8cb5c6ecb0d2206000f1' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('tcp_billing_factor_revisions') IS NOT NULL OR
         to_regclass('tcp_billing_cycle_settlements') IS NOT NULL OR
         to_regclass('tcp_billing_adjustments') IS NOT NULL OR
         to_regclass('tcp_billing_write_receipts') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 137 requires the exact verified 136 release head'
            USING ERRCODE = 'P1376';
    END IF;
END;
$migration_137$;

LOCK TABLE access_scopes, users, memberships, roles, role_permissions, permissions IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO permissions(name,description) VALUES
    ('tcp_billing.read','Read TCP billing factor revisions and immutable cycle settlements'),
    ('tcp_billing.manage','Schedule TCP billing factor revisions'),
    ('tcp_billing.settle','Settle finalized TCP traffic cycles'),
    ('tcp_billing.adjust','Append TCP billing refunds and voids')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
CROSS JOIN (VALUES
    ('tcp_billing.read'),('tcp_billing.manage'),('tcp_billing.settle'),('tcp_billing.adjust')
) permission(name)
WHERE role.system_role AND role.name IN ('platform_owner','platform_admin')
ON CONFLICT DO NOTHING;

CREATE TABLE tcp_billing_factor_revisions (
    id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision>0),
    factor text NOT NULL CHECK (factor IN ('1.0','1.1')),
    factor_numerator bigint NOT NULL CHECK (factor_numerator>0),
    factor_denominator bigint NOT NULL CHECK (factor_denominator>0),
    effective_at timestamptz NOT NULL CHECK (isfinite(effective_at)),
    reason text NOT NULL CHECK (reason=btrim(reason) AND length(reason) BETWEEN 1 AND 512),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    CHECK ((factor='1.0' AND factor_numerator=1 AND factor_denominator=1) OR
           (factor='1.1' AND factor_numerator=11 AND factor_denominator=10)),
    UNIQUE (platform_scope_id,revision),
    UNIQUE (platform_scope_id,effective_at),
    UNIQUE (id,platform_scope_id)
);

INSERT INTO tcp_billing_factor_revisions(
    id,platform_scope_id,revision,factor,factor_numerator,factor_denominator,
    effective_at,reason,created_by_user_id,created_at)
SELECT gen_random_uuid(),scope.id,1,'1.0',1,1,'2000-01-01T00:00:00Z'::timestamptz,
       '默认 TCP 流量计费系数',membership.user_id,now()
FROM access_scopes scope
JOIN LATERAL (
    SELECT membership.user_id
    FROM memberships membership
    JOIN users user_row ON user_row.id=membership.user_id AND user_row.status='active'
    WHERE membership.scope_id=scope.id AND membership.status='active'
    ORDER BY membership.created_at,membership.user_id LIMIT 1
) membership ON true
WHERE scope.kind='platform';

CREATE TABLE tcp_billing_cycle_settlements (
    id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    cycle_key text NOT NULL CHECK (cycle_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    cycle_starts_at timestamptz NOT NULL CHECK (isfinite(cycle_starts_at)),
    cycle_ends_at timestamptz NOT NULL CHECK (isfinite(cycle_ends_at) AND cycle_ends_at>cycle_starts_at),
    timezone text NOT NULL CHECK (timezone ~ '^[A-Za-z_][A-Za-z0-9_+.-]*(/[A-Za-z0-9_+.-]+)+$'),
    metric_version bigint NOT NULL CHECK (metric_version=1),
    source_watermark text NOT NULL CHECK (source_watermark=btrim(source_watermark) AND length(source_watermark) BETWEEN 1 AND 512),
    finalized_through timestamptz NOT NULL CHECK (isfinite(finalized_through) AND finalized_through>=cycle_ends_at),
    evidence_sha256 bytea NOT NULL CHECK (octet_length(evidence_sha256)=32),
    raw_tcp_bytes bigint NOT NULL CHECK (raw_tcp_bytes>=0),
    billed_tcp_bytes bigint NOT NULL CHECK (billed_tcp_bytes>=0),
    factor_revision_id uuid NOT NULL,
    factor_revision bigint NOT NULL CHECK (factor_revision>0),
    factor text NOT NULL CHECK (factor IN ('1.0','1.1')),
    factor_numerator bigint NOT NULL CHECK (factor_numerator>0),
    factor_denominator bigint NOT NULL CHECK (factor_denominator>0),
    factor_effective_at timestamptz NOT NULL CHECK (isfinite(factor_effective_at)),
    settled_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    settled_at timestamptz NOT NULL CHECK (isfinite(settled_at)),
    CHECK ((factor='1.0' AND factor_numerator=1 AND factor_denominator=1) OR
           (factor='1.1' AND factor_numerator=11 AND factor_denominator=10)),
    CHECK (billed_tcp_bytes::numeric = ceil(raw_tcp_bytes::numeric * factor_numerator::numeric / factor_denominator::numeric)),
    FOREIGN KEY (factor_revision_id,platform_scope_id)
        REFERENCES tcp_billing_factor_revisions(id,platform_scope_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id,subscription_id,cycle_key),
    UNIQUE (tenant_scope_id,subscription_id,source_watermark),
    UNIQUE (id,platform_scope_id)
);

CREATE TABLE tcp_billing_adjustments (
    id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    settlement_id uuid NOT NULL,
    platform_scope_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('refund','void')),
    amount_bytes bigint NOT NULL CHECK (amount_bytes>0),
    reason text NOT NULL CHECK (reason=btrim(reason) AND length(reason) BETWEEN 1 AND 512),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (settlement_id,platform_scope_id)
        REFERENCES tcp_billing_cycle_settlements(id,platform_scope_id) ON DELETE RESTRICT,
    UNIQUE (id,platform_scope_id)
);

CREATE TABLE tcp_billing_write_receipts (
    id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('factor.schedule','cycle.settle','settlement.adjust')),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    resource_id uuid NOT NULL CHECK (resource_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id,actor_user_id,actor_session_id,operation,idempotency_key),
    UNIQUE (actor_scope_id,actor_user_id,actor_session_id,operation,request_id)
);

CREATE FUNCTION enforce_tcp_billing_adjustment_balance_137()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    billed bigint;
    adjusted bigint;
    remaining bigint;
BEGIN
    SELECT billed_tcp_bytes INTO billed
    FROM tcp_billing_cycle_settlements
    WHERE id=NEW.settlement_id AND platform_scope_id=NEW.platform_scope_id
    FOR UPDATE;
    IF billed IS NULL THEN
        RAISE EXCEPTION 'tcp billing settlement not found' USING ERRCODE='P1370';
    END IF;
    SELECT COALESCE(sum(amount_bytes),0) INTO adjusted
    FROM tcp_billing_adjustments WHERE settlement_id=NEW.settlement_id;
    remaining := billed-adjusted;
    IF NEW.amount_bytes>remaining THEN
        RAISE EXCEPTION 'tcp billing adjustment exceeds remaining billed bytes' USING ERRCODE='P1371';
    END IF;
    IF NEW.operation='void' AND NEW.amount_bytes<>remaining THEN
        RAISE EXCEPTION 'void must reverse all remaining billed bytes' USING ERRCODE='P1372';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tcp_billing_adjustment_balance_137
BEFORE INSERT ON tcp_billing_adjustments
FOR EACH ROW EXECUTE FUNCTION enforce_tcp_billing_adjustment_balance_137();

CREATE FUNCTION prevent_tcp_billing_fact_mutation_137()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME='tcp_billing_cycle_settlements' THEN
        RAISE EXCEPTION 'tcp billing settlements are append-only' USING ERRCODE='P1373';
    ELSIF TG_TABLE_NAME='tcp_billing_adjustments' THEN
        RAISE EXCEPTION 'tcp billing adjustments are append-only' USING ERRCODE='P1374';
    ELSE
        RAISE EXCEPTION 'tcp billing facts are append-only' USING ERRCODE='P1375';
    END IF;
END;
$$;

CREATE TRIGGER tcp_billing_factor_revisions_immutable_137
BEFORE UPDATE OR DELETE ON tcp_billing_factor_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_factor_revisions_no_truncate_137
BEFORE TRUNCATE ON tcp_billing_factor_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_settlements_immutable_137
BEFORE UPDATE OR DELETE ON tcp_billing_cycle_settlements
FOR EACH ROW EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_settlements_no_truncate_137
BEFORE TRUNCATE ON tcp_billing_cycle_settlements
FOR EACH STATEMENT EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_adjustments_immutable_137
BEFORE UPDATE OR DELETE ON tcp_billing_adjustments
FOR EACH ROW EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_adjustments_no_truncate_137
BEFORE TRUNCATE ON tcp_billing_adjustments
FOR EACH STATEMENT EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_write_receipts_immutable_137
BEFORE UPDATE OR DELETE ON tcp_billing_write_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();
CREATE TRIGGER tcp_billing_write_receipts_no_truncate_137
BEFORE TRUNCATE ON tcp_billing_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_tcp_billing_fact_mutation_137();

REVOKE ALL ON FUNCTION enforce_tcp_billing_adjustment_balance_137() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_tcp_billing_fact_mutation_137() FROM PUBLIC;
