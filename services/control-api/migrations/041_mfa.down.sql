DROP TRIGGER mfa_step_up_uses_append_only ON mfa_step_up_uses;
DROP TRIGGER mfa_step_up_proofs_append_only ON mfa_step_up_proofs;
DROP TRIGGER mfa_recovery_code_consumptions_append_only ON mfa_recovery_code_consumptions;
DROP TRIGGER mfa_recovery_codes_append_only ON mfa_recovery_codes;
DROP TRIGGER mfa_credential_events_append_only ON mfa_credential_events;
DROP TRIGGER mfa_credentials_append_only ON mfa_credentials;
DROP FUNCTION prevent_mfa_fact_mutation();

DROP TRIGGER mfa_step_up_uses_validate ON mfa_step_up_uses;
DROP FUNCTION validate_mfa_step_up_use();
DROP TRIGGER mfa_step_up_proofs_validate ON mfa_step_up_proofs;
DROP FUNCTION validate_mfa_step_up_proof();
DROP TRIGGER mfa_recovery_code_consumptions_validate ON mfa_recovery_code_consumptions;
DROP FUNCTION validate_mfa_recovery_consumption();
DROP TRIGGER mfa_credential_events_validate ON mfa_credential_events;
DROP FUNCTION validate_mfa_credential_event();

DROP TABLE mfa_step_up_uses;
DROP TABLE mfa_step_up_proofs;
DROP TABLE mfa_recovery_code_consumptions;
DROP TABLE mfa_credential_events;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_credentials;
