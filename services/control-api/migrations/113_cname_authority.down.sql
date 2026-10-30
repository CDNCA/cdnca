LOCK TABLE schema_migrations,
    cname_allocation_requests,
    cname_site_bindings,
    cname_hostname_claims,
    cname_allocations,
    sites,
    dns_zones,
    package_subscriptions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 113 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 113 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=113 AND migration_id='113_cname_authority'
          AND checksum_sha256='ac4716d79decdb1076dbc19a5bf9ac9400d997f198cd56a8639b3d1924c12ccb'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=112 AND migration_id='112_dns_reconcile_actor_receipts'
          AND checksum_sha256='d26988f21844ba759a0345ad1aed1fd3d40156c6a22dd2e382736987348a8017'
          AND down_checksum_sha256='d329f963d275aad130595d2e4f477e9cfd5416e06bec2761e78760db8f4f1aa0'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 113 rollback requires the exact verified 113 release head'
            USING ERRCODE='P1130';
    END IF;

    IF EXISTS (SELECT 1 FROM cname_allocations) OR
       EXISTS (SELECT 1 FROM cname_hostname_claims) OR
       EXISTS (SELECT 1 FROM cname_site_bindings) OR
       EXISTS (SELECT 1 FROM cname_allocation_requests) OR
       EXISTS (SELECT 1 FROM dns_zones WHERE is_default) OR
       EXISTS (
        SELECT 1 FROM sites
        WHERE package_subscription_id IS NOT NULL OR cname_mode IS NOT NULL OR
              cname_domain IS NOT NULL OR cname_hostname2 IS NOT NULL OR
              cname_state IS NOT NULL OR cname_task_id IS NOT NULL OR
              cname_current_revision IS NOT NULL OR cname_lkg_revision IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 113 rollback would discard CNAME authority facts'
            USING ERRCODE='P1136';
    END IF;
END;
$$;

DROP TRIGGER cname_allocation_requests_validate_113 ON cname_allocation_requests;
DROP TRIGGER cname_allocation_requests_no_truncate_113 ON cname_allocation_requests;
DROP TRIGGER cname_allocation_requests_append_only_113 ON cname_allocation_requests;
DROP TRIGGER sites_cname_authority_validate_113 ON sites;
DROP TRIGGER cname_site_bindings_validate_113 ON cname_site_bindings;
DROP TRIGGER cname_hostname_claims_no_truncate_113 ON cname_hostname_claims;
DROP TRIGGER cname_hostname_claims_append_only_113 ON cname_hostname_claims;
DROP TRIGGER cname_allocations_consistent_113 ON cname_allocations;
DROP TRIGGER cname_allocations_validate_113 ON cname_allocations;

DROP FUNCTION validate_cname_allocation_request_113();
DROP FUNCTION protect_cname_allocation_request_113();
DROP FUNCTION validate_sites_cname_authority_113();
DROP FUNCTION validate_cname_site_binding_113();
DROP FUNCTION protect_cname_hostname_claim_113();
DROP FUNCTION assert_cname_allocation_consistency_113();
DROP FUNCTION validate_cname_allocation_113();

DROP TABLE cname_allocation_requests;
DROP TABLE cname_site_bindings;

ALTER TABLE cname_allocations
    DROP CONSTRAINT cname_allocations_lkg_claim_113_fk,
    DROP CONSTRAINT cname_allocations_current_claim_113_fk;

DROP TABLE cname_hostname_claims;
DROP TABLE cname_allocations;

ALTER TABLE sites
    DROP CONSTRAINT sites_cname_authority_113_check,
    DROP CONSTRAINT sites_cname_revision_113_check,
    DROP CONSTRAINT sites_cname_state_113_check,
    DROP CONSTRAINT sites_cname_hostname2_113_check,
    DROP CONSTRAINT sites_cname_domain_113_check,
    DROP CONSTRAINT sites_cname_mode_113_check,
    DROP CONSTRAINT sites_cname_projection_113_check,
    DROP CONSTRAINT sites_cname_task_113_fk,
    DROP CONSTRAINT sites_package_subscription_owner_113_fk,
    DROP CONSTRAINT sites_scope_package_subscription_product_113_fk,
    DROP CONSTRAINT sites_scope_id_owner_113_key,
    DROP COLUMN cname_lkg_revision,
    DROP COLUMN cname_current_revision,
    DROP COLUMN cname_task_id,
    DROP COLUMN cname_state,
    DROP COLUMN cname_hostname2,
    DROP COLUMN cname_domain,
    DROP COLUMN cname_mode,
    DROP COLUMN package_subscription_id;

ALTER TABLE package_subscriptions
    DROP CONSTRAINT package_subscriptions_scope_id_product_113_key;

DROP INDEX dns_zones_scope_default_113_uidx;

ALTER TABLE dns_zones
    DROP CONSTRAINT dns_zones_scope_zone_provider_name_113_key,
    DROP COLUMN is_default;
