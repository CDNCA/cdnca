LOCK TABLE certificate_assets,
           certificate_asset_versions,
           certificate_asset_private_key_envelope_facts,
           certificate_asset_activation_facts,
           certificate_asset_revocation_facts,
           certificate_site_binding_facts,
           certificate_asset_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_assets) OR
       EXISTS (SELECT 1 FROM certificate_asset_versions) OR
       EXISTS (SELECT 1 FROM certificate_asset_private_key_envelope_facts) OR
       EXISTS (SELECT 1 FROM certificate_asset_activation_facts) OR
       EXISTS (SELECT 1 FROM certificate_asset_revocation_facts) OR
       EXISTS (SELECT 1 FROM certificate_site_binding_facts) OR
       EXISTS (SELECT 1 FROM certificate_asset_write_requests) THEN
        RAISE EXCEPTION 'cannot roll back certificate assets while 039 facts exist';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS certificate_asset_write_requests_no_truncate ON certificate_asset_write_requests;
DROP TRIGGER IF EXISTS certificate_asset_write_requests_protect ON certificate_asset_write_requests;
DROP FUNCTION IF EXISTS protect_certificate_asset_write_request();

DROP TRIGGER IF EXISTS certificate_site_bindings_no_truncate ON certificate_site_binding_facts;
DROP TRIGGER IF EXISTS certificate_site_bindings_immutable ON certificate_site_binding_facts;
DROP FUNCTION IF EXISTS protect_certificate_site_binding();

DROP TRIGGER IF EXISTS certificate_asset_revocations_no_truncate ON certificate_asset_revocation_facts;
DROP TRIGGER IF EXISTS certificate_asset_revocations_immutable ON certificate_asset_revocation_facts;
DROP FUNCTION IF EXISTS protect_certificate_asset_revocation();

DROP TRIGGER IF EXISTS certificate_asset_activations_no_truncate ON certificate_asset_activation_facts;
DROP TRIGGER IF EXISTS certificate_asset_activations_immutable ON certificate_asset_activation_facts;
DROP FUNCTION IF EXISTS protect_certificate_asset_activation();
DROP TRIGGER IF EXISTS certificate_activation_bindings_required ON certificate_asset_activation_facts;
DROP FUNCTION IF EXISTS validate_certificate_activation_bindings_commit();

DROP TRIGGER IF EXISTS certificate_asset_private_key_envelopes_no_truncate ON certificate_asset_private_key_envelope_facts;
DROP TRIGGER IF EXISTS certificate_asset_private_key_envelopes_immutable ON certificate_asset_private_key_envelope_facts;
DROP FUNCTION IF EXISTS protect_certificate_asset_private_key_envelope();

DROP TRIGGER IF EXISTS certificate_asset_version_envelope_required ON certificate_asset_versions;
DROP FUNCTION IF EXISTS validate_certificate_asset_version_envelope_commit();

DROP TRIGGER IF EXISTS certificate_asset_versions_no_truncate ON certificate_asset_versions;
DROP TRIGGER IF EXISTS certificate_asset_versions_immutable ON certificate_asset_versions;
DROP FUNCTION IF EXISTS protect_certificate_asset_version();

DROP TRIGGER IF EXISTS certificate_assets_no_truncate ON certificate_assets;
DROP TRIGGER IF EXISTS certificate_assets_protect ON certificate_assets;
DROP FUNCTION IF EXISTS protect_certificate_asset();

DROP TABLE IF EXISTS certificate_asset_write_requests;
DROP TABLE IF EXISTS certificate_site_binding_facts;
DROP TABLE IF EXISTS certificate_asset_revocation_facts;
DROP TABLE IF EXISTS certificate_asset_activation_facts;
DROP TABLE IF EXISTS certificate_asset_private_key_envelope_facts;
DROP TABLE IF EXISTS certificate_asset_versions;
DROP TRIGGER IF EXISTS certificate_assets_tenant_scope ON certificate_assets;
DROP TABLE IF EXISTS certificate_assets;
DROP FUNCTION IF EXISTS assert_certificate_asset_tenant_scope();
DROP FUNCTION IF EXISTS certificate_asset_domain_covered(text[], text);
DROP FUNCTION IF EXISTS certificate_asset_valid_dns_names(text[]);
