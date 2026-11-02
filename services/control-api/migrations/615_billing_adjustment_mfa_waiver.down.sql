-- 615 回退：已有免二次验证的调账事实无法用 614 及更早的结构表达（证明列 NOT NULL），拒绝回退；
-- 否则恢复 100 的请求触发器、435 的审批触发器、原 CHECK 与 NOT NULL，删除 waiver 列与函数。
LOCK TABLE schema_migrations, billing_adjustment_requests, billing_adjustment_decisions,
    custom_role_revisions, custom_role_deactivations, custom_role_grants, custom_role_grant_revocations IN ACCESS EXCLUSIVE MODE;

DO $migration_615_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 615 OR
       (SELECT max(version) FROM schema_migrations) <> 615 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=615 AND
        migration_id='615_billing_adjustment_mfa_waiver' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 615 down requires the exact verified migration head' USING ERRCODE='P6151';
    END IF;
    IF EXISTS (SELECT 1 FROM billing_adjustment_requests WHERE proposed_step_up_waived) OR
       EXISTS (SELECT 1 FROM billing_adjustment_decisions WHERE approved_step_up_waived) OR
       EXISTS (SELECT 1 FROM custom_role_revisions WHERE step_up_method='none') OR
       EXISTS (SELECT 1 FROM custom_role_deactivations WHERE step_up_method='none') OR
       EXISTS (SELECT 1 FROM custom_role_grants WHERE step_up_method='none') OR
       EXISTS (SELECT 1 FROM custom_role_grant_revocations WHERE step_up_method='none') THEN
        RAISE EXCEPTION 'migration 615 rollback would keep billing adjustments approved without MFA' USING ERRCODE='P6152';
    END IF;
END;
$migration_615_down$;

CREATE OR REPLACE FUNCTION validate_billing_adjustment_request_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    proof_max_uses smallint;
    proof_action text;
    proof_audience text;
    use_actor_user uuid;
    use_actor_scope uuid;
    use_session uuid;
    use_tenant uuid;
    use_binding bytea;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM billing_accounts account
        JOIN access_scopes scope ON scope.id=account.scope_id AND scope.kind='tenant'
        JOIN tenants tenant ON tenant.id=scope.tenant_id
        WHERE account.id=NEW.target_account_id AND account.scope_id=NEW.target_scope_id
          AND account.kind='tenant_liability' AND tenant.id=NEW.target_tenant_id
    ) THEN
        RAISE EXCEPTION 'invalid billing adjustment target authority'
            USING ERRCODE='P1002';
    END IF;
    SELECT proof.max_uses,proof.action,proof.audience,
           use_row.actor_user_id,use_row.actor_scope_id,use_row.auth_session_id,
           use_row.tenant_id,use_row.resource_binding_sha256
      INTO proof_max_uses,proof_action,proof_audience,use_actor_user,use_actor_scope,
           use_session,use_tenant,use_binding
    FROM mfa_step_up_uses use_row
    JOIN mfa_step_up_proofs proof ON proof.id=use_row.proof_id
    WHERE use_row.proof_id=NEW.proposed_step_up_proof_id
      AND use_row.use_ordinal=NEW.proposed_step_up_use_ordinal;
    IF proof_max_uses IS DISTINCT FROM 1 OR proof_action IS DISTINCT FROM 'billing.adjustment.propose'
       OR proof_audience IS DISTINCT FROM 'billing-adjustments'
       OR use_actor_user IS DISTINCT FROM NEW.proposed_by_user_id
       OR use_actor_scope IS DISTINCT FROM NEW.proposed_by_scope_id
       OR use_session IS DISTINCT FROM NEW.proposed_by_session_id
       OR use_tenant IS DISTINCT FROM NEW.target_tenant_id
       OR use_binding IS DISTINCT FROM NEW.step_up_binding_digest THEN
        RAISE EXCEPTION 'billing adjustment proposal requires max_uses=1 bound MFA evidence'
            USING ERRCODE='P1002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_billing_adjustment_decision_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request billing_adjustment_requests%ROWTYPE;
    proof_max_uses smallint;
    proof_action text;
    proof_audience text;
    use_actor_user uuid;
    use_actor_scope uuid;
    use_session uuid;
    use_tenant uuid;
    use_binding bytea;
BEGIN
    SELECT * INTO request FROM billing_adjustment_requests
    WHERE id=NEW.adjustment_request_id;
    IF NOT FOUND OR NEW.decided_at<request.proposed_at OR NEW.decided_at>=request.expires_at THEN
        RAISE EXCEPTION 'billing adjustment request is not decidable'
            USING ERRCODE='P1002';
    END IF;
    IF NEW.decision='cancelled' THEN
        IF NEW.approved_by_user_id<>request.proposed_by_user_id
           OR NEW.approved_by_scope_id<>request.proposed_by_scope_id
           OR NEW.approved_by_session_id<>request.proposed_by_session_id THEN
            RAISE EXCEPTION 'only the proposal session may cancel a billing adjustment'
                USING ERRCODE='P1002';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.approved_by_user_id=request.proposed_by_user_id AND
       NOT control_platform_admin_435(NEW.approved_by_user_id,NEW.approved_by_scope_id) THEN
        RAISE EXCEPTION 'approved_by_user_id <> proposed_by_user_id is required'
            USING ERRCODE='P1002';
    END IF;
    SELECT proof.max_uses,proof.action,proof.audience,
           use_row.actor_user_id,use_row.actor_scope_id,use_row.auth_session_id,
           use_row.tenant_id,use_row.resource_binding_sha256
      INTO proof_max_uses,proof_action,proof_audience,use_actor_user,use_actor_scope,
           use_session,use_tenant,use_binding
    FROM mfa_step_up_uses use_row
    JOIN mfa_step_up_proofs proof ON proof.id=use_row.proof_id
    WHERE use_row.proof_id=NEW.approved_step_up_proof_id
      AND use_row.use_ordinal=NEW.approved_step_up_use_ordinal;
    IF proof_max_uses IS DISTINCT FROM 1
       OR proof_action IS DISTINCT FROM 'billing.adjustment.'||(CASE NEW.decision
            WHEN 'approved' THEN 'approve' ELSE 'reject' END)
       OR proof_audience IS DISTINCT FROM 'billing-adjustments'
       OR use_actor_user IS DISTINCT FROM NEW.approved_by_user_id
       OR use_actor_scope IS DISTINCT FROM NEW.approved_by_scope_id
       OR use_session IS DISTINCT FROM NEW.approved_by_session_id
       OR use_tenant IS DISTINCT FROM request.target_tenant_id
       OR use_binding IS DISTINCT FROM NEW.step_up_binding_digest THEN
        RAISE EXCEPTION 'billing adjustment decision requires max_uses=1 bound MFA evidence'
            USING ERRCODE='P1002';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE billing_adjustment_decisions
    DROP CONSTRAINT billing_adjustment_decisions_step_up_authority_615,
    DROP COLUMN approved_step_up_waived,
    ADD CONSTRAINT billing_adjustment_decisions_check CHECK(
        (decision IN ('approved','rejected') AND step_up_binding_digest IS NOT NULL
            AND approved_step_up_proof_id IS NOT NULL AND approved_step_up_use_ordinal=1)
        OR
        (decision='cancelled' AND step_up_binding_digest IS NULL
            AND approved_step_up_proof_id IS NULL AND approved_step_up_use_ordinal IS NULL)
    );

ALTER TABLE billing_adjustment_requests
    DROP CONSTRAINT billing_adjustment_requests_step_up_authority_615,
    DROP COLUMN proposed_step_up_waived,
    ALTER COLUMN proposed_step_up_proof_id SET NOT NULL,
    ALTER COLUMN proposed_step_up_use_ordinal SET NOT NULL;

DROP FUNCTION billing_adjustment_mfa_waived_615(uuid,uuid,uuid,text,text,uuid,bytea);

ALTER TABLE custom_role_revisions
    DROP CONSTRAINT custom_role_revisions_step_up_method_check,
    ADD CONSTRAINT custom_role_revisions_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn'));

ALTER TABLE custom_role_deactivations
    DROP CONSTRAINT custom_role_deactivations_step_up_method_check,
    ADD CONSTRAINT custom_role_deactivations_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn'));

ALTER TABLE custom_role_grants
    DROP CONSTRAINT custom_role_grants_step_up_method_check,
    ADD CONSTRAINT custom_role_grants_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn'));

ALTER TABLE custom_role_grant_revocations
    DROP CONSTRAINT custom_role_grant_revocations_step_up_method_check,
    ADD CONSTRAINT custom_role_grant_revocations_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn'));
