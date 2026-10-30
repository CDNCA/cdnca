LOCK TABLE schema_migrations,
    package_offer_lifecycle_lock,
    package_offer_publication_heads,
    package_offer_publication_events,
    package_catalog_audit_links_090,
    package_product_state_facts_090,
    package_group_state_facts_090,
    package_catalog_commit_watermark_090,
    package_catalog_write_requests,
    package_products,
    package_product_versions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 90 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 90 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=90 AND migration_id='090_package_offer_publication'
		  AND checksum_sha256='1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 090 rollback requires the verified 090 head'
            USING ERRCODE = 'P9000';
    END IF;
    IF EXISTS (SELECT 1 FROM package_offer_publication_events) OR
	   EXISTS (SELECT 1 FROM package_offer_publication_heads) OR
	   EXISTS (SELECT 1 FROM package_catalog_audit_links_090) OR
	   EXISTS (SELECT 1 FROM package_group_state_facts_090 WHERE catalog_sequence > 0) OR
	   EXISTS (SELECT 1 FROM package_product_state_facts_090 WHERE catalog_sequence > 0) OR
	   EXISTS (SELECT 1 FROM package_catalog_write_requests
		WHERE operation IN ('package.product.publish','package.product.withdraw')) THEN
        RAISE EXCEPTION 'migration 090 rollback would discard package offer publication facts'
            USING ERRCODE = 'P9001';
    END IF;
END;
$$;

DROP TRIGGER package_catalog_audit_links_no_truncate_090 ON package_catalog_audit_links_090;
DROP TRIGGER package_catalog_audit_links_protected_090 ON package_catalog_audit_links_090;
DROP TRIGGER package_product_state_facts_no_truncate_090 ON package_product_state_facts_090;
DROP TRIGGER package_product_state_facts_protected_090 ON package_product_state_facts_090;
DROP TRIGGER package_group_state_facts_no_truncate_090 ON package_group_state_facts_090;
DROP TRIGGER package_group_state_facts_protected_090 ON package_group_state_facts_090;
DROP TRIGGER package_catalog_watermark_no_truncate_090 ON package_catalog_commit_watermark_090;
DROP TRIGGER package_catalog_watermark_protected_090 ON package_catalog_commit_watermark_090;
DROP TRIGGER package_catalog_watermark_completed_090 ON package_catalog_commit_watermark_090;
DROP FUNCTION require_package_catalog_sequence_completion_090();
DROP FUNCTION protect_package_catalog_state_090();
DROP FUNCTION current_package_catalog_xid_090();
DROP TRIGGER package_product_state_facts_audited_090 ON package_product_state_facts_090;
DROP FUNCTION require_package_product_state_audit_090();
DROP TRIGGER package_group_state_facts_audited_090 ON package_group_state_facts_090;
DROP FUNCTION require_package_group_state_audit_090();
DROP TRIGGER audit_events_bind_package_catalog_090 ON audit_events;
DROP FUNCTION bind_package_catalog_audit_090();
DROP TRIGGER package_products_capture_state_090 ON package_products;
DROP FUNCTION capture_package_product_state_090();
DROP TRIGGER package_groups_capture_state_090 ON package_groups;
DROP FUNCTION capture_package_group_state_090();

DROP TRIGGER package_offer_publication_heads_no_truncate ON package_offer_publication_heads;
DROP TRIGGER package_offer_publication_heads_no_delete ON package_offer_publication_heads;
DROP TRIGGER package_offer_publication_heads_projected_090 ON package_offer_publication_heads;
DROP FUNCTION protect_package_offer_publication_head_090();
DROP TRIGGER package_offer_publication_events_completed_090 ON package_offer_publication_events;
DROP FUNCTION require_package_offer_publication_completion_090();
DROP TRIGGER package_offer_catalog_requests_no_truncate_090 ON package_catalog_write_requests;
DROP TRIGGER package_offer_catalog_requests_provenance_immutable_090 ON package_catalog_write_requests;
DROP FUNCTION protect_package_offer_catalog_request_090();
DROP TRIGGER package_offer_publication_events_no_truncate ON package_offer_publication_events;
DROP TRIGGER package_offer_publication_events_append_only ON package_offer_publication_events;
DROP TRIGGER package_offer_lifecycle_lock_no_truncate ON package_offer_lifecycle_lock;
DROP TRIGGER package_offer_lifecycle_lock_immutable ON package_offer_lifecycle_lock;
DROP FUNCTION protect_package_offer_publication_fact_090();
DROP TRIGGER package_offer_publication_events_project_head_090 ON package_offer_publication_events;
DROP FUNCTION project_package_offer_publication_head_090();
DROP TRIGGER package_offer_publication_events_validate_090 ON package_offer_publication_events;
DROP FUNCTION validate_package_offer_publication_event_090();
DROP FUNCTION next_package_catalog_sequence_090();
DROP FUNCTION package_offer_spec_publishable_090(jsonb,timestamptz);
DROP TABLE package_offer_publication_heads;
DROP TABLE package_offer_publication_events;
DROP TABLE package_offer_lifecycle_lock;
DROP TABLE package_catalog_audit_links_090;
DROP TABLE package_product_state_facts_090;
DROP TABLE package_group_state_facts_090;
DROP TABLE package_catalog_commit_watermark_090;

ALTER TABLE package_catalog_write_requests
    DROP CONSTRAINT package_catalog_write_requests_operation_check;
ALTER TABLE package_catalog_write_requests
    ADD CONSTRAINT package_catalog_write_requests_operation_check CHECK (operation IN (
        'package.group.create',
        'package.group.update',
        'package.group.delete',
        'package.product.create',
        'package.product.update',
        'package.product.delete'
    ));
