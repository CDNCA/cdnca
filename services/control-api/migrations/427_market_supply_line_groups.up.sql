LOCK TABLE schema_migrations, node_line_groups IN ACCESS EXCLUSIVE MODE;

DO $migration_427_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 426 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 426 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=426 AND
        migration_id='426_security_activation_v1_root_removed' AND
        checksum_sha256='5b19a7a2723ac905988003efc5871be164047e09a213287275bf9f8a33b96c73' AND
        down_checksum_sha256='15150a88347442da8612864873d0c98ed49d1dc5f53a4e0b747b822cd069820b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='node_line_groups' AND column_name='purpose'
       ) THEN
        RAISE EXCEPTION 'migration 427 requires the exact verified 426 release head' USING ERRCODE='P4270';
    END IF;
END;
$migration_427_up$;

-- 427（r136 ML-09，ADR 0012 §3.3；占位，登记号 430，合入时改号）。
-- A seller composes a market supply from one or more of its nodes; the
-- controller keeps it as a hidden platform line group with
-- purpose='market_supply', so publication, probing and the market pool
-- inventory (marketprobe, by line group) stay as they are. Ordinary line
-- group lists, package resources and the line group API show only
-- purpose='general'. purpose is fixed at creation: the protect trigger
-- refuses a change, so a general group can never turn hidden (or back).
ALTER TABLE node_line_groups
    ADD COLUMN purpose text NOT NULL DEFAULT 'general',
    ADD CONSTRAINT node_line_groups_purpose_427_check CHECK (purpose IN ('general', 'market_supply'));

-- Hidden supply groups belong to the platform scope only (marketprobe and
-- marketsupply resolve pools there).
CREATE FUNCTION assert_node_line_group_purpose_427()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.purpose IS DISTINCT FROM OLD.purpose THEN
        RAISE EXCEPTION 'node line group purpose is fixed at creation' USING ERRCODE='P4271';
    END IF;
    IF NEW.purpose = 'market_supply' AND NOT EXISTS (
        SELECT 1 FROM access_scopes scope WHERE scope.id=NEW.tenant_scope_id AND scope.kind='platform'
    ) THEN
        RAISE EXCEPTION 'market supply line groups belong to the platform scope' USING ERRCODE='P4272';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION assert_node_line_group_purpose_427() FROM PUBLIC;

CREATE TRIGGER node_line_groups_purpose_427
BEFORE INSERT OR UPDATE ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_purpose_427();

CREATE INDEX node_line_groups_market_supply_427_idx
    ON node_line_groups (tenant_scope_id, id) WHERE purpose = 'market_supply' AND deleted_at IS NULL;
