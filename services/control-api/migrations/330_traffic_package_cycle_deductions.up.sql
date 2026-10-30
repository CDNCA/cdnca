LOCK TABLE schema_migrations, package_subscriptions, traffic_package_grants IN ACCESS EXCLUSIVE MODE;

DO $migration_330_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 329 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 329 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=329 AND
        migration_id='329_ip_intel_node_distribution' AND
        checksum_sha256='478749ae18f6af81b650f2c2f50845cc7ea7e2f201a70aeb3d1189622c715187' AND
        down_checksum_sha256='65b1265253a15eccf0d664ac868cf7161a49b38be38d499cf5559d6781b92d07' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.traffic_package_cycle_deductions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 330 requires the exact verified 329 release head' USING ERRCODE='P3300';
    END IF;
END;
$migration_330_up$;

-- FX58: global traffic packages cover a subscription's traffic beyond its
-- cycle limit. One row per deduction batch; covered_after_bytes is the
-- cumulative package coverage of the cycle, so replaying the same usage (same
-- target overage) deducts nothing. sequence serializes batches of one cycle and
-- the primary key rejects a second writer of the same batch.
CREATE TABLE traffic_package_cycle_deductions (
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    sequence bigint NOT NULL CHECK (sequence > 0),
    deduction_id uuid NOT NULL UNIQUE,
    target_overage_bytes bigint NOT NULL CHECK (target_overage_bytes > 0),
    deducted_bytes bigint NOT NULL CHECK (deducted_bytes > 0),
    covered_after_bytes bigint NOT NULL CHECK (covered_after_bytes >= deducted_bytes AND covered_after_bytes <= target_overage_bytes),
    event_ids uuid[] NOT NULL CHECK (cardinality(event_ids) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, subscription_id, period_key, sequence),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE TRIGGER traffic_package_cycle_deductions_append_only_330
BEFORE UPDATE OR DELETE ON traffic_package_cycle_deductions
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_cycle_deductions_no_truncate_330
BEFORE TRUNCATE ON traffic_package_cycle_deductions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

-- The expiry sweeper finds due grants across tenants.
CREATE INDEX traffic_package_grants_due_330
    ON traffic_package_grants (expires_at, bucket_id) WHERE status IN ('active', 'exhausted');

REVOKE ALL ON traffic_package_cycle_deductions FROM PUBLIC;
GRANT SELECT, INSERT ON traffic_package_cycle_deductions TO cdnca_control_app, cdnca_control_runtime;
