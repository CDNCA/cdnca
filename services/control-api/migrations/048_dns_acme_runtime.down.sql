LOCK TABLE acme_issuance_operations,
           acme_issuance_operation_events,
           certificate_orders,
           certificate_assets,
           certificate_asset_versions,
           certificate_asset_private_key_envelope_facts,
           certificate_asset_activation_facts,
           certificate_asset_revocation_facts,
           certificate_site_binding_facts,
           certificate_asset_write_requests,
           acme_issuance_challenge_attempts,
           acme_issuance_challenge_events,
           dns_acme_outbox,
           dns_acme_write_requests,
           acme_tenant_key_facts,
           acme_account_registration_facts,
           acme_renewal_claim_facts,
           dns_providers,
           dns_zones,
           dns_records
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_orders)
       OR EXISTS (SELECT 1 FROM dns_acme_outbox)
       OR EXISTS (SELECT 1 FROM acme_issuance_operations)
       OR EXISTS (SELECT 1 FROM acme_issuance_operation_events)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_attempts)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_events)
       OR EXISTS (SELECT 1 FROM acme_tenant_key_facts)
       OR EXISTS (SELECT 1 FROM acme_account_registration_facts)
       OR EXISTS (SELECT 1 FROM acme_renewal_claim_facts)
       OR EXISTS (SELECT 1 FROM certificate_assets WHERE source = 'acme')
       OR EXISTS (SELECT 1 FROM certificate_asset_versions WHERE acme_order_id IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back DNS ACME runtime while order, key, account, publication, renewal, or ACME asset facts exist'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS acme_renewal_claim_facts_no_truncate_048 ON acme_renewal_claim_facts;
DROP TRIGGER IF EXISTS acme_renewal_claim_facts_immutable_048 ON acme_renewal_claim_facts;
DROP TRIGGER IF EXISTS acme_renewal_claim_facts_validate_048 ON acme_renewal_claim_facts;
DROP TRIGGER IF EXISTS dns_acme_outbox_no_truncate_048 ON dns_acme_outbox;
DROP TRIGGER IF EXISTS dns_acme_outbox_runtime_048 ON dns_acme_outbox;
DROP TRIGGER IF EXISTS certificate_orders_no_truncate_048 ON certificate_orders;
DROP TRIGGER IF EXISTS certificate_orders_runtime_048 ON certificate_orders;
DROP TRIGGER IF EXISTS acme_issuance_challenge_publication_048 ON acme_issuance_challenge_events;
DROP TRIGGER IF EXISTS acme_issuance_operation_events_runtime_048 ON acme_issuance_operation_events;
DROP TRIGGER IF EXISTS acme_issuance_operations_binding_048 ON acme_issuance_operations;
DROP TRIGGER IF EXISTS acme_account_registration_facts_no_truncate_048 ON acme_account_registration_facts;
DROP TRIGGER IF EXISTS acme_account_registration_facts_immutable_048 ON acme_account_registration_facts;
DROP TRIGGER IF EXISTS acme_account_registration_facts_validate_048 ON acme_account_registration_facts;
DROP TRIGGER IF EXISTS acme_tenant_key_facts_no_truncate_048 ON acme_tenant_key_facts;
DROP TRIGGER IF EXISTS acme_tenant_key_facts_immutable_048 ON acme_tenant_key_facts;
DROP TRIGGER IF EXISTS acme_tenant_key_facts_validate_048 ON acme_tenant_key_facts;

DROP FUNCTION IF EXISTS validate_acme_renewal_claim_fact_048();
DROP FUNCTION IF EXISTS protect_dns_acme_outbox_048();
DROP FUNCTION IF EXISTS protect_certificate_order_runtime_048();
DROP FUNCTION IF EXISTS validate_acme_challenge_publication_048();
DROP FUNCTION IF EXISTS validate_acme_operation_event_runtime_048();
DROP FUNCTION IF EXISTS validate_acme_operation_binding_048();
DROP FUNCTION IF EXISTS validate_acme_account_registration_fact_048();
DROP FUNCTION IF EXISTS validate_acme_tenant_key_fact_048();
DROP FUNCTION IF EXISTS acme_runtime_actor_is_active_048(uuid, uuid);
DROP FUNCTION IF EXISTS reject_dns_acme_runtime_fact_mutation_048();

DROP INDEX IF EXISTS acme_issuance_challenge_remote_ref_idx_048;
ALTER TABLE acme_issuance_challenge_events
    DROP CONSTRAINT IF EXISTS acme_issuance_challenge_publication_shape_048,
    DROP COLUMN IF EXISTS exact_value_sha256,
    DROP COLUMN IF EXISTS remote_record_ref,
    DROP COLUMN IF EXISTS provider_ref;

DROP INDEX IF EXISTS acme_issuance_operations_certificate_key_idx_048;
DROP INDEX IF EXISTS acme_issuance_operations_account_key_idx_048;
DROP INDEX IF EXISTS acme_issuance_operations_provider_idx_048;
DROP INDEX IF EXISTS acme_issuance_operations_actor_idx_048;
ALTER TABLE acme_issuance_operations
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_order_unique_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_request_binding_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_order_identity_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_certificate_key_fk_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_account_key_fk_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_provider_fk_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_actor_fk_048,
    DROP CONSTRAINT IF EXISTS acme_issuance_operations_order_fk_048,
    DROP COLUMN IF EXISTS account_key_ref,
    DROP COLUMN IF EXISTS dns_provider_id,
    DROP COLUMN IF EXISTS actor_user_id,
    DROP COLUMN IF EXISTS certificate_order_id;

DROP INDEX IF EXISTS dns_acme_outbox_takeover_idx_048;
DROP INDEX IF EXISTS dns_acme_outbox_claim_idx_048;
DROP INDEX IF EXISTS dns_acme_outbox_order_idx_048;
ALTER TABLE dns_acme_outbox
    DROP CONSTRAINT IF EXISTS dns_acme_outbox_lease_contract_048,
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS last_error_code,
    DROP COLUMN IF EXISTS lease_expires_at,
    DROP COLUMN IF EXISTS lease_token;
CREATE INDEX dns_acme_outbox_pending_idx
    ON dns_acme_outbox (next_attempt_at, id) WHERE status IN ('pending', 'failed');

DROP INDEX IF EXISTS certificate_orders_issued_asset_idx_048;
DROP INDEX IF EXISTS certificate_orders_updated_actor_idx_048;
DROP INDEX IF EXISTS certificate_orders_created_actor_idx_048;
ALTER TABLE certificate_orders
    DROP CONSTRAINT IF EXISTS certificate_orders_issuance_refs_048,
    DROP CONSTRAINT IF EXISTS certificate_orders_issuance_urls_048,
    DROP CONSTRAINT IF EXISTS certificate_orders_issuance_contract_048,
    DROP CONSTRAINT IF EXISTS certificate_orders_updated_actor_fk_048,
    DROP CONSTRAINT IF EXISTS certificate_orders_created_actor_fk_048,
    DROP CONSTRAINT IF EXISTS certificate_orders_issued_asset_fk_048,
    DROP COLUMN IF EXISTS certificate_url,
    DROP COLUMN IF EXISTS authorization_urls_sha256,
    DROP COLUMN IF EXISTS external_order_url,
    DROP COLUMN IF EXISTS certificate_key_ref,
    DROP COLUMN IF EXISTS acme_account_key_ref,
    DROP COLUMN IF EXISTS acme_directory_url,
    DROP COLUMN IF EXISTS leaf_spki_sha256,
    DROP COLUMN IF EXISTS leaf_fingerprint_sha256,
    DROP COLUMN IF EXISTS issued_at,
    DROP COLUMN IF EXISTS issued_asset_version_id,
    DROP COLUMN IF EXISTS issued_asset_id;

DROP TABLE IF EXISTS acme_renewal_claim_facts;
DROP TABLE IF EXISTS acme_account_registration_facts;
DROP TABLE IF EXISTS acme_tenant_key_facts;
