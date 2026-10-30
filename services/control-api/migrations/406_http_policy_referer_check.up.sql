LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_406_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 405 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 405 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=405 AND
        migration_id='405_waf_policy_settings' AND
        checksum_sha256='5d0a1cdfefe13fb721140a02396c81a5fce019c6355af0e9b5c2f01cbbc4a6d0' AND
        down_checksum_sha256='f163b0ad8450a6fa06672a052059d97fc393430589b0258218d7e299acd04189' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('http_policy_referer_check_valid_406(jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 406 requires the exact verified 405 release head' USING ERRCODE='P4060';
    END IF;
END;
$migration_406_up$;

-- ge-waf S8 (GoEdge parity: 防盗链): the site HTTP policy document gains
-- referer_check (httppolicycontrol.RefererCheckPolicy); null is no check.
-- Domains are host names or "*.example.com"; deny and allow lists never share
-- a domain, and a check restricts something (same domain, allow or deny list).
CREATE FUNCTION http_policy_referer_domains_valid_406(domains jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE item jsonb;
DECLARE host_part text;
BEGIN
    IF domains IS NULL OR jsonb_typeof(domains) <> 'array' OR jsonb_array_length(domains) > 64 OR
       (SELECT count(*) FROM jsonb_array_elements(domains)) <>
       (SELECT count(DISTINCT element.item_value #>> '{}') FROM jsonb_array_elements(domains) AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element.item_value FROM jsonb_array_elements(domains) AS element(item_value) LOOP
        IF jsonb_typeof(item) <> 'string' THEN RETURN false; END IF;
        host_part := item #>> '{}';
        IF left(host_part, 2) = '*.' THEN
            host_part := substr(host_part, 3);
            IF position('.' in host_part) = 0 THEN RETURN false; END IF;
        END IF;
        IF NOT http_policy_hostname_valid_056(host_part) THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION http_policy_referer_check_valid_406(check_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE item jsonb;
BEGIN
    IF check_value IS NULL OR jsonb_typeof(check_value) = 'null' THEN RETURN true; END IF;
    IF NOT http_policy_exact_keys_056(check_value,
        ARRAY['allow_empty','allow_same_domain','allowed_domains','denied_domains','check_origin','extensions']) OR
       jsonb_typeof(check_value -> 'allow_empty') <> 'boolean' OR
       jsonb_typeof(check_value -> 'allow_same_domain') <> 'boolean' OR
       jsonb_typeof(check_value -> 'check_origin') <> 'boolean' OR
       NOT http_policy_referer_domains_valid_406(check_value -> 'allowed_domains') OR
       NOT http_policy_referer_domains_valid_406(check_value -> 'denied_domains') OR
       check_value -> 'allowed_domains' ?| ARRAY(SELECT jsonb_array_elements_text(check_value -> 'denied_domains')) OR
       (NOT (check_value ->> 'allow_same_domain')::boolean AND
        jsonb_array_length(check_value -> 'allowed_domains') = 0 AND
        jsonb_array_length(check_value -> 'denied_domains') = 0) OR
       jsonb_typeof(check_value -> 'extensions') <> 'array' OR jsonb_array_length(check_value -> 'extensions') > 32 OR
       (SELECT count(*) FROM jsonb_array_elements(check_value -> 'extensions')) <>
       (SELECT count(DISTINCT element.item_value #>> '{}') FROM jsonb_array_elements(check_value -> 'extensions') AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element.item_value FROM jsonb_array_elements(check_value -> 'extensions') AS element(item_value) LOOP
        IF jsonb_typeof(item) <> 'string' OR (item #>> '{}') !~ '^[a-z0-9]{1,16}$' THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION http_policy_document_valid_056(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN http_policy_exact_keys_056(document, ARRAY[
        'schema_version','policy_id','tenant_scope_id','site_id','site_owner_user_id','revision',
        'max_upload_bytes','request_headers','response_headers','rewrites',
        'redirect_allowed_hosts','redirects','cors','referer_check','enabled','deleted'
    ]) AND document ->> 'schema_version' = 'cdnca.control.http-policy/v1' AND
        (document ->> 'policy_id')::uuid IS NOT NULL AND
        (document ->> 'tenant_scope_id')::uuid IS NOT NULL AND
        (document ->> 'site_id')::uuid IS NOT NULL AND
        (document ->> 'site_owner_user_id')::uuid IS NOT NULL AND
        jsonb_typeof(document -> 'revision') = 'number' AND
        (document ->> 'revision') ~ '^[0-9]+$' AND (document ->> 'revision')::numeric > 0 AND
        jsonb_typeof(document -> 'max_upload_bytes') = 'number' AND
        (document ->> 'max_upload_bytes') ~ '^[0-9]+$' AND
        (document ->> 'max_upload_bytes')::numeric BETWEEN 1 AND 1073741824 AND
        http_policy_header_actions_valid_056(document -> 'request_headers', true) AND
        http_policy_header_actions_valid_056(document -> 'response_headers', false) AND
        http_policy_rewrite_chain_valid_056(document -> 'rewrites') AND
        http_policy_authorities_valid_056(document -> 'redirect_allowed_hosts') AND
        http_policy_redirects_valid_056(document -> 'redirects', document -> 'redirect_allowed_hosts') AND
        http_policy_rule_conflicts_valid_056(document -> 'rewrites', document -> 'redirects') AND
        http_policy_cors_valid_056(document -> 'cors') AND
        http_policy_referer_check_valid_406(document -> 'referer_check') AND
        jsonb_typeof(document -> 'enabled') = 'boolean' AND
        jsonb_typeof(document -> 'deleted') = 'boolean' AND
        NOT ((document ->> 'deleted')::boolean AND (document ->> 'enabled')::boolean);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END;
$$;
