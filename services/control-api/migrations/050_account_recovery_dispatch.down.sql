DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM account_recovery_dispatch_claims) THEN
        RAISE EXCEPTION 'cannot roll back account recovery dispatch while claims exist'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TRIGGER account_recovery_dispatch_claims_no_truncate_050 ON account_recovery_dispatch_claims;
DROP FUNCTION prevent_account_recovery_dispatch_truncate_050();
DROP TRIGGER account_recovery_dispatch_claims_protected_050 ON account_recovery_dispatch_claims;
DROP FUNCTION protect_account_recovery_dispatch_claim_050();
DROP TRIGGER account_recovery_dispatch_claims_validate_050 ON account_recovery_dispatch_claims;
DROP FUNCTION validate_account_recovery_dispatch_claim_050();
DROP INDEX account_recovery_dispatch_claims_expiry_050;
DROP TABLE account_recovery_dispatch_claims;
