LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_274_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 273 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 273 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=273 AND
        migration_id='273_validator_search_path' AND
        checksum_sha256='65997dc158a20dc1ab2d809362cbd4e4d2117554c411830d84eac8e7e0d48bf7' AND
        down_checksum_sha256='e72851fe9670e3686de8bdea22d445a32de9be91a985519d84f549f4b2d6b471' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 274 requires the exact verified 273 release head' USING ERRCODE='P2740';
    END IF;
END;
$migration_274_up$;

ALTER TABLE node_line_endpoints
    ADD COLUMN sort_order integer NOT NULL DEFAULT 100,
    ADD CONSTRAINT node_line_endpoints_sort_order_274_check
        CHECK (sort_order BETWEEN 0 AND 999999);

CREATE INDEX node_line_endpoints_sort_274_idx
    ON node_line_endpoints (
        tenant_scope_id, line_group_id, config_revision,
        priority, sort_order, id
    );
