DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM origin_auth_credentials) OR
       EXISTS (SELECT 1 FROM origin_auth_credential_revisions) OR
       EXISTS (SELECT 1 FROM origin_auth_rules) OR
       EXISTS (SELECT 1 FROM origin_auth_rule_revisions) OR
       EXISTS (SELECT 1 FROM origin_auth_publications) OR
       EXISTS (SELECT 1 FROM origin_auth_write_requests) THEN
        RAISE EXCEPTION 'cannot remove origin authentication control schema while facts exist';
    END IF;
END;
$$;

DROP TRIGGER origin_auth_write_requests_no_truncate ON origin_auth_write_requests;
DROP TRIGGER origin_auth_publications_no_truncate ON origin_auth_publications;
DROP TRIGGER origin_auth_rule_revisions_no_truncate ON origin_auth_rule_revisions;
DROP TRIGGER origin_auth_rules_no_truncate ON origin_auth_rules;
DROP TRIGGER origin_auth_credential_revisions_no_truncate ON origin_auth_credential_revisions;
DROP TRIGGER origin_auth_credentials_no_truncate ON origin_auth_credentials;
DROP FUNCTION prevent_origin_auth_truncate();

DROP TRIGGER origin_auth_publications_append_only ON origin_auth_publications;
DROP TRIGGER origin_auth_rule_revisions_append_only ON origin_auth_rule_revisions;
DROP TRIGGER origin_auth_rules_append_only ON origin_auth_rules;
DROP TRIGGER origin_auth_credential_revisions_append_only ON origin_auth_credential_revisions;
DROP TRIGGER origin_auth_credentials_append_only ON origin_auth_credentials;
DROP FUNCTION prevent_origin_auth_fact_mutation();

DROP TRIGGER origin_auth_write_requests_protected ON origin_auth_write_requests;
DROP FUNCTION protect_origin_auth_write_request();
DROP TRIGGER origin_auth_publications_validate ON origin_auth_publications;
DROP FUNCTION validate_origin_auth_publication();
DROP TRIGGER origin_auth_rule_revisions_validate ON origin_auth_rule_revisions;
DROP FUNCTION validate_origin_auth_rule_revision();
DROP TRIGGER origin_auth_rules_validate_insert ON origin_auth_rules;
DROP FUNCTION validate_origin_auth_rule_identity();
DROP TRIGGER origin_auth_credential_revisions_validate ON origin_auth_credential_revisions;
DROP FUNCTION validate_origin_auth_credential_revision();
DROP TRIGGER origin_auth_credentials_validate_insert ON origin_auth_credentials;
DROP FUNCTION validate_origin_auth_credential_identity();
DROP FUNCTION origin_auth_has_pending_write(uuid, uuid, uuid, text, text, text);
DROP FUNCTION origin_auth_has_audit(uuid, uuid, text, text, text, text, text);
DROP FUNCTION origin_auth_actor_has_permission(uuid, uuid, text);

DROP TRIGGER roles_origin_auth_permissions_055 ON roles;
DROP FUNCTION grant_origin_auth_permissions_055();

DROP TABLE origin_auth_write_requests;
DROP TABLE origin_auth_publications;
DROP TABLE origin_auth_rule_revisions;
DROP TABLE origin_auth_rules;
DROP TABLE origin_auth_credential_revisions;
DROP TABLE origin_auth_credentials;

DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('origin_auth.read', 'origin_auth.manage');
DELETE FROM role_permissions WHERE permission_name IN ('origin_auth.read', 'origin_auth.manage');
DELETE FROM permissions WHERE name IN ('origin_auth.read', 'origin_auth.manage');
