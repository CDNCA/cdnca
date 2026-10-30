LOCK TABLE account_recovery_rate_windows, account_recovery_challenges,
    account_recovery_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM account_recovery_write_requests) OR
       EXISTS (SELECT 1 FROM account_recovery_challenges) OR
       EXISTS (SELECT 1 FROM account_recovery_rate_windows) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot roll back account recovery while facts exist';
    END IF;
END;
$$;

DROP TRIGGER account_recovery_rate_windows_no_truncate ON account_recovery_rate_windows;
DROP TRIGGER account_recovery_write_requests_no_truncate ON account_recovery_write_requests;
DROP TRIGGER account_recovery_challenges_no_truncate ON account_recovery_challenges;
DROP FUNCTION prevent_account_recovery_truncate();

DROP TRIGGER account_recovery_rate_windows_protected ON account_recovery_rate_windows;
DROP FUNCTION protect_account_recovery_rate_window();
DROP TRIGGER account_recovery_write_requests_protected ON account_recovery_write_requests;
DROP FUNCTION protect_account_recovery_write_request();
DROP TRIGGER account_recovery_challenges_protected ON account_recovery_challenges;
DROP FUNCTION protect_account_recovery_challenge();
DROP TRIGGER account_recovery_challenges_validate_insert ON account_recovery_challenges;
DROP FUNCTION validate_account_recovery_challenge_insert();
DROP TRIGGER account_recovery_rate_windows_scope ON account_recovery_rate_windows;
DROP TRIGGER account_recovery_write_requests_scope ON account_recovery_write_requests;
DROP FUNCTION validate_account_recovery_scope();

DROP TABLE account_recovery_rate_windows;
DROP TABLE account_recovery_challenges;
DROP TABLE account_recovery_write_requests;
