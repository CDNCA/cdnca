LOCK TABLE schema_migrations, node_network_inventory_reports IN ACCESS EXCLUSIVE MODE;
DO $migration_271_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 271 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 271 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=271 AND migration_id='271_node_network_inventory' AND
        checksum_sha256='994f0b28e574bf8df27edef0e1ff5583cf9241dfdecfb5bfd0eaa2b227a2a19c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
           migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
           checksum_sha256 IS NULL OR down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL) THEN
        RAISE EXCEPTION 'migration 271 rollback requires the exact verified 271 release head' USING ERRCODE='P2711';
    END IF;
    IF EXISTS (SELECT 1 FROM node_network_inventory_reports) THEN
        RAISE EXCEPTION 'migration 271 rollback cannot discard node address evidence' USING ERRCODE='P2712';
    END IF;
END;
$migration_271_down$;
DROP VIEW node_network_inventory_latest;
DROP TABLE node_network_inventory_reports;
DROP FUNCTION protect_node_network_inventory_271();
