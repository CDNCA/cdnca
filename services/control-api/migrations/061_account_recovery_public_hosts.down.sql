LOCK TABLE account_recovery_public_hosts, account_recovery_public_host_revisions
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM account_recovery_public_hosts) OR
       EXISTS (SELECT 1 FROM account_recovery_public_host_revisions) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot remove account recovery public host schema while facts exist';
    END IF;
END;
$$;

DROP TRIGGER account_recovery_public_hosts_no_delete ON account_recovery_public_hosts;
DROP FUNCTION prevent_account_recovery_public_host_removal();

DROP TRIGGER account_recovery_public_host_revisions_append_only
    ON account_recovery_public_host_revisions;
DROP FUNCTION prevent_account_recovery_public_host_fact_mutation();

DROP TRIGGER account_recovery_public_host_revision_projection_required
    ON account_recovery_public_host_revisions;
DROP FUNCTION require_account_recovery_public_host_projection();

DROP TRIGGER account_recovery_public_hosts_validate ON account_recovery_public_hosts;
DROP FUNCTION validate_account_recovery_public_host_projection();

DROP TRIGGER account_recovery_public_host_revisions_validate
    ON account_recovery_public_host_revisions;
DROP FUNCTION validate_account_recovery_public_host_revision();

DROP TABLE account_recovery_public_hosts;
DROP TABLE account_recovery_public_host_revisions;
DROP FUNCTION account_recovery_public_hostname_valid(text);
