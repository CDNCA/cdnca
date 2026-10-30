LOCK TABLE acme_issuance_challenge_events,
           acme_issuance_challenge_attempts,
           acme_issuance_operation_events,
           acme_issuance_operations
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM acme_issuance_operations)
       OR EXISTS (SELECT 1 FROM acme_issuance_operation_events)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_attempts)
       OR EXISTS (SELECT 1 FROM acme_issuance_challenge_events) THEN
        RAISE EXCEPTION 'cannot roll back ACME worker while 047 facts exist' USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS acme_issuance_challenge_events_immutable ON acme_issuance_challenge_events;
DROP TRIGGER IF EXISTS acme_issuance_challenge_events_validate ON acme_issuance_challenge_events;
DROP TRIGGER IF EXISTS acme_issuance_challenge_attempts_immutable ON acme_issuance_challenge_attempts;
DROP TRIGGER IF EXISTS acme_issuance_challenge_attempts_validate ON acme_issuance_challenge_attempts;
DROP TRIGGER IF EXISTS acme_issuance_challenge_requires_intent ON acme_issuance_challenge_attempts;
DROP TRIGGER IF EXISTS acme_issuance_operation_events_immutable ON acme_issuance_operation_events;
DROP TRIGGER IF EXISTS acme_issuance_operation_events_validate ON acme_issuance_operation_events;
DROP TRIGGER IF EXISTS acme_issuance_operations_immutable ON acme_issuance_operations;
DROP TRIGGER IF EXISTS acme_issuance_operation_requires_claim ON acme_issuance_operations;
DROP TRIGGER IF EXISTS acme_issuance_operation_snapshot_validate_047 ON acme_issuance_operations;

DROP FUNCTION IF EXISTS validate_acme_challenge_event();
DROP FUNCTION IF EXISTS validate_acme_challenge_attempt();
DROP FUNCTION IF EXISTS validate_acme_issuance_operation_event();
DROP FUNCTION IF EXISTS assert_acme_challenge_has_intent();
DROP FUNCTION IF EXISTS assert_acme_operation_has_initial_event();
DROP FUNCTION IF EXISTS protect_acme_issuance_facts();
DROP FUNCTION IF EXISTS validate_acme_issuance_operation_snapshot_047();

DROP TABLE IF EXISTS acme_issuance_challenge_events;
DROP TABLE IF EXISTS acme_issuance_challenge_attempts;
DROP TABLE IF EXISTS acme_issuance_operation_events;
DROP TABLE IF EXISTS acme_issuance_operations;
