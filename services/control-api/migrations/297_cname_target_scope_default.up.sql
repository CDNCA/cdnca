LOCK TABLE schema_migrations, cname_allocation_targets IN ACCESS EXCLUSIVE MODE;

DO $migration_297_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 296 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 296 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=296 AND
        migration_id='296_market_buyer' AND
        checksum_sha256='6a8d7b946285732f64191ffb4c11f8eda5b31f3b40dae0937f8361a347910b65' AND
        down_checksum_sha256='8fbc7c1c7a40d8e8b8c7104c396a67043866662ed4158fd3ebeaf7f6f704d52b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.default_cname_target_node_group_scope_297()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 297 requires the exact verified 296 release head' USING ERRCODE='P2970';
    END IF;
END;
$migration_297_up$;

-- 287 added node_group_scope_id NOT NULL without a default. A writer that
-- predates 287 (control-api 1.0.33 after a binary rollback) names only
-- tenant_scope_id; every target it freezes uses the tenant's own group, so
-- the scope defaults to it. "a_" sorts first among the BEFORE triggers, so
-- the 287 guard still checks the filled value.
CREATE FUNCTION default_cname_target_node_group_scope_297() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.node_group_scope_id IS NULL THEN
        NEW.node_group_scope_id := NEW.tenant_scope_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER a_cname_allocation_targets_scope_297
BEFORE INSERT ON cname_allocation_targets
FOR EACH ROW EXECUTE FUNCTION default_cname_target_node_group_scope_297();
REVOKE ALL ON FUNCTION default_cname_target_node_group_scope_297() FROM PUBLIC;
