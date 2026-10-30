DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM http_policy_revisions)
       OR EXISTS (SELECT 1 FROM http_policy_write_requests)
       OR EXISTS (SELECT 1 FROM http_policy_publication_heads) THEN
        RAISE EXCEPTION 'migration 056 contains irreversible HTTP policy facts';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        WHERE permission.permission_name IN ('http_policies.read', 'http_policies.manage')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY['http_policies.read', 'http_policies.manage']::text[]
    ) THEN
        RAISE EXCEPTION 'migration 056 HTTP policy permissions are referenced by custom RBAC facts';
    END IF;
END;
$$;

DROP TRIGGER http_policy_revisions_audited_056 ON http_policy_revisions;
DROP FUNCTION assert_http_policy_revision_audited_056();
DROP TRIGGER http_policy_write_requests_no_truncate_056 ON http_policy_write_requests;
DROP TRIGGER http_policy_write_requests_guard_056 ON http_policy_write_requests;
DROP FUNCTION protect_http_policy_write_request_056();
DROP TRIGGER http_policy_revisions_no_truncate_056 ON http_policy_revisions;
DROP TRIGGER http_policy_revisions_append_only_056 ON http_policy_revisions;
DROP FUNCTION protect_http_policy_revision_056();
DROP TRIGGER http_policy_publication_heads_no_truncate_056 ON http_policy_publication_heads;
DROP TRIGGER http_policy_publication_heads_guard_056 ON http_policy_publication_heads;
DROP TRIGGER http_policies_no_truncate_056 ON http_policies;
DROP TRIGGER http_policies_projection_guard_056 ON http_policies;
DROP FUNCTION protect_http_policy_projection_056();
DROP TRIGGER http_policy_revisions_project_056 ON http_policy_revisions;
DROP FUNCTION project_http_policy_revision_056();
DROP TRIGGER http_policy_revisions_validate_056 ON http_policy_revisions;
DROP FUNCTION validate_http_policy_revision_056();
DROP FUNCTION http_policy_actor_can_056(uuid, uuid, uuid, text);
DROP FUNCTION http_policy_document_valid_056(jsonb);
DROP FUNCTION http_policy_cors_valid_056(jsonb);
DROP FUNCTION http_policy_rule_conflicts_valid_056(jsonb, jsonb);
DROP FUNCTION http_policy_redirects_valid_056(jsonb, jsonb);
DROP FUNCTION http_policy_authorities_valid_056(jsonb);
DROP FUNCTION http_policy_authority_valid_056(text);
DROP FUNCTION http_policy_hostname_valid_056(text);
DROP FUNCTION http_policy_rewrite_chain_valid_056(jsonb);
DROP FUNCTION http_policy_rewrites_valid_056(jsonb);
DROP FUNCTION http_policy_header_actions_valid_056(jsonb, boolean);
DROP FUNCTION http_policy_string_array_valid_056(jsonb, integer, boolean, boolean);
DROP FUNCTION http_policy_path_valid_056(text, text);
DROP FUNCTION http_policy_token_valid_056(text);
DROP FUNCTION http_policy_identifier_valid_056(text);
DROP FUNCTION http_policy_exact_keys_056(jsonb, text[]);

DROP TABLE http_policy_write_requests;
DROP TABLE http_policy_publication_heads;
DROP TABLE http_policy_revisions;
DROP TABLE http_policies;

DROP TRIGGER roles_http_policy_permissions_056 ON roles;
DROP FUNCTION grant_http_policy_permissions_056();

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('http_policies.read', 'http_policies.manage');
DELETE FROM role_permissions
WHERE permission_name IN ('http_policies.read', 'http_policies.manage');
DELETE FROM permissions
WHERE name IN ('http_policies.read', 'http_policies.manage');
