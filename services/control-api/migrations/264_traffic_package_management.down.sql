LOCK TABLE schema_migrations, traffic_package_product_snapshots, traffic_package_management_facts IN ACCESS EXCLUSIVE MODE;
DO $migration_264_down_head$
BEGIN
 IF (SELECT count(*) FROM schema_migrations) <> 264 OR
    (SELECT min(version) FROM schema_migrations) <> 1 OR
    (SELECT max(version) FROM schema_migrations) <> 264 OR
    NOT EXISTS (
      SELECT 1 FROM schema_migrations
      WHERE version=264 AND migration_id='264_traffic_package_management'
        AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR
    NOT EXISTS (
      SELECT 1 FROM schema_migrations
      WHERE version=263 AND migration_id='263_package_addon_management'
        AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
  RAISE EXCEPTION 'migration 264 rollback requires the verified 264 release head' USING ERRCODE='P2641';
 END IF;
END;
$migration_264_down_head$;

-- Rollback refuses to discard live metadata; retain migration when rolling back binaries.
DO $migration_264_down_data$
BEGIN
 IF EXISTS(SELECT 1 FROM traffic_package_management_facts) OR EXISTS (SELECT 1 FROM traffic_package_product_snapshots WHERE remark <> '' OR cardinality(allowed_package_ids)>0) THEN
 RAISE EXCEPTION 'rollback would discard traffic package metadata';
 END IF;
END;
$migration_264_down_data$;
DROP TRIGGER traffic_package_grants_management ON traffic_package_grants;
DROP FUNCTION require_traffic_product_management();
DROP TABLE traffic_package_management_facts;
DROP FUNCTION require_traffic_package_management_audit();
DROP FUNCTION validate_traffic_package_management_fact();
ALTER TABLE traffic_package_product_snapshots DROP COLUMN remark, DROP COLUMN allowed_package_ids;
