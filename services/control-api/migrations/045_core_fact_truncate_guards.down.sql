DO $migration$
DECLARE
    table_name text;
    has_facts boolean;
    protected_tables text[] := ARRAY[
        'audit_events',
        'billing_transactions',
        'billing_postings',
        'artifact_signing_keys',
        'config_versions',
        'configuration_artifacts',
        'rollouts',
        'node_deployments',
        'node_deployment_artifacts',
        'edge_command_outbox',
        'deployment_status_events',
        'artifact_fetch_requests',
        'node_config_reconciliations',
        'edge_config_publications',
        'traffic_package_product_snapshots',
        'traffic_package_buckets',
        'traffic_package_events',
        'traffic_package_ledger_entries',
        'node_ca_key_epochs',
        'node_ca_key_epoch_revocations',
        'node_certificates',
        'node_certificate_renewal_requests',
        'node_certificate_revocations',
        'node_certificate_events',
        'identity_verification_materials',
        'identity_verification_state_events',
        'identity_verification_submissions',
        'identity_verification_review_assignments',
        'identity_verification_reviews',
        'identity_verified_persons',
        'identity_verified_organizations',
        'admin_impersonation_grants',
        'admin_impersonation_sessions',
        'admin_impersonation_revocations',
        'certificate_asset_versions',
        'certificate_asset_private_key_envelope_facts',
        'certificate_asset_activation_facts',
        'certificate_asset_revocation_facts',
        'certificate_site_binding_facts',
        'account_recovery_challenges',
        'mfa_credentials',
        'mfa_credential_events',
        'mfa_recovery_codes',
        'mfa_recovery_code_consumptions',
        'mfa_step_up_proofs',
        'mfa_step_up_uses',
        'custom_role_revisions',
        'custom_role_deactivations',
        'custom_role_grants',
        'custom_role_grant_revocations',
        'custom_rbac_write_requests',
        'announcement_versions',
        'announcement_audience_users',
        'announcement_audience_groups',
        'announcement_recipient_snapshots',
        'announcement_inbox_events',
        'promotion_policies',
        'promotion_policy_versions',
        'promotion_policy_product_targets',
        'promotion_policy_tenant_targets',
        'promotion_quotes',
        'promotion_quote_policies',
        'promotion_reservations',
        'promotion_reservation_events',
        'promotion_renewal_price_snapshots',
        'promotion_renewal_bindings',
        'promotion_adjustment_decisions'
    ];
BEGIN
    FOREACH table_name IN ARRAY protected_tables LOOP
        EXECUTE format('LOCK TABLE %I IN ACCESS EXCLUSIVE MODE', table_name);
    END LOOP;

    FOREACH table_name IN ARRAY protected_tables LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I)', table_name) INTO has_facts;
        IF has_facts THEN
            RAISE EXCEPTION 'migration 045 cannot be rolled back while protected table % contains facts',
                table_name USING ERRCODE = 'P0001';
        END IF;
    END LOOP;

    FOREACH table_name IN ARRAY protected_tables LOOP
        EXECUTE format(
            'DROP TRIGGER zz_core_fact_truncate_guard_045 ON %I',
            table_name
        );
    END LOOP;
END;
$migration$;

DROP FUNCTION prevent_core_fact_truncate_045();
