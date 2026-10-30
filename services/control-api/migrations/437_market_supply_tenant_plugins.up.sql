LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_437_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 436 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 436 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=436 AND
        migration_id='436_installation_ban_state' AND
        checksum_sha256='7e2f043d0fc778775acdd2c0d412baa46fd3fd49de1ec0fd3b849f21dc0f1c89' AND
        down_checksum_sha256='a161099ea6b8bb3cfe31773f0652e29ba3fc008409d2867563b58af00ff0e5b8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_supply_tenant_plugins') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 437 requires the exact verified 436 release head' USING ERRCODE='P4370';
    END IF;
END;
$migration_437_up$;

-- 437（r136 ML-25/ML-22，ADR 0012 §19.2、§20；占位，登记号 440，合入时改号）。
-- What the latest applied supply grant of a market tenant (mkt-) allows on
-- this leaf: the node plugins of grant tags.plugins and the supplier's
-- automatic defence caps (grant autodefense_caps, NULL = unconstrained).
-- A tenant without a row is not a market tenant and is not restricted.
-- Publication (rule pack mounts) and the automatic defence snapshot read it:
-- a setting depending on a plugin outside the set is left out on the nodes
-- while the tenant's own configuration stays as it is (U14); a grant that
-- includes the plugin again restores it with the next publication.
CREATE TABLE market_supply_tenant_plugins (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE CASCADE,
    grant_id uuid NOT NULL,
    plugins text[] NOT NULL CHECK (cardinality(plugins) <= 32 AND array_position(plugins, NULL) IS NULL),
    autodefense_caps jsonb CHECK (autodefense_caps IS NULL OR jsonb_typeof(autodefense_caps) = 'object'),
    updated_at timestamptz NOT NULL
);
