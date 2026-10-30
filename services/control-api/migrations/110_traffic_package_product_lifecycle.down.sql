LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 110 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 110 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=110 AND migration_id='110_traffic_package_product_lifecycle'
          AND checksum_sha256='e645c599cb1b1ffe3dfe0a53a5acdaa87d04d97518dbf19747aceef5d8dcf44b'
          AND integrity_state='verified'
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=109 AND migration_id='109_site_origin_route_control'
          AND checksum_sha256='d6b3a67fa2504b048f969317c7605868ebe3ad4edf122286d546edfb023310c2'
          AND down_checksum_sha256='098fd79ed88641247b2f787b18cd170a5082c42f717b1e907491ceb6ecb61719'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 110 rollback requires a verified release head' USING ERRCODE='P1100';
    END IF;
    IF EXISTS (SELECT 1 FROM traffic_package_product_lifecycle_facts WHERE sequence > 0) OR
       EXISTS (SELECT 1 FROM traffic_package_product_lifecycle_audit_links_110) THEN
        RAISE EXCEPTION 'migration 110 rollback would discard product lifecycle history' USING ERRCODE='P1101';
    END IF;
END;
$$;

DROP TRIGGER traffic_package_product_lifecycle_facts_no_truncate_110
    ON traffic_package_product_lifecycle_facts;
DROP TRIGGER traffic_package_product_lifecycle_facts_append_only_110
    ON traffic_package_product_lifecycle_facts;
DROP TRIGGER traffic_package_product_lifecycle_facts_audited_110
    ON traffic_package_product_lifecycle_facts;
DROP TRIGGER audit_events_bind_traffic_package_product_lifecycle_110 ON audit_events;
DROP FUNCTION require_traffic_package_product_lifecycle_audit_110();
DROP FUNCTION bind_traffic_package_product_lifecycle_audit_110();
DROP TABLE traffic_package_product_lifecycle_audit_links_110;
DROP TRIGGER traffic_package_grants_require_enabled_product_110 ON traffic_package_grants;
DROP FUNCTION require_traffic_package_grant_enabled_product_110();
DROP TRIGGER traffic_package_product_snapshots_lifecycle_baseline_110
    ON traffic_package_product_snapshots;
DROP FUNCTION append_traffic_package_product_lifecycle_baseline_110();
DROP TABLE traffic_package_product_lifecycle_facts;
DROP TABLE traffic_package_product_lifecycle_watermarks;
