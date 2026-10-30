LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_406_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 406 OR
       (SELECT max(version) FROM schema_migrations) <> 406 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=406 AND
        migration_id='406_http_policy_referer_check' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 406 down requires the exact verified migration head' USING ERRCODE='P4061';
    END IF;
    -- Revisions written under 406 carry the referer_check key, which the
    -- 056 document contract (and the code before it) does not know.
    IF EXISTS (SELECT 1 FROM http_policy_revisions WHERE document ? 'referer_check') THEN
        RAISE EXCEPTION 'HTTP policy revisions carry referer_check; rollback of 406 is unsafe' USING ERRCODE='P4062';
    END IF;
END;
$migration_406_down$;

CREATE OR REPLACE FUNCTION http_policy_document_valid_056(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN http_policy_exact_keys_056(document, ARRAY[
        'schema_version','policy_id','tenant_scope_id','site_id','site_owner_user_id','revision',
        'max_upload_bytes','request_headers','response_headers','rewrites',
        'redirect_allowed_hosts','redirects','cors','enabled','deleted'
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
        jsonb_typeof(document -> 'enabled') = 'boolean' AND
        jsonb_typeof(document -> 'deleted') = 'boolean' AND
        NOT ((document ->> 'deleted')::boolean AND (document ->> 'enabled')::boolean);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END;
$$;

DROP FUNCTION http_policy_referer_check_valid_406(jsonb);
DROP FUNCTION http_policy_referer_domains_valid_406(jsonb);
