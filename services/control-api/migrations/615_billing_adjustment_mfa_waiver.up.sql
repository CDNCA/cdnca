-- 615（r136 fix-mfaoptional2，用户 11-01 决定；前驱 614_purchased_subscription_owner，合入时按连号改号）：
--   操作者没启用 MFA 时任何操作都不提示、不阻挡二次验证。人工调账的提议/审批原先由
--   迁移 100（审批由 435 改写）在数据库里要求一条 max_uses=1、绑定本次写入的 MFA 证明
--   （proposed/approved_step_up_proof_id NOT NULL + 外键到 mfa_step_up_uses），没启用 MFA
--   的平台管理员因此永远做不了调账。
--   这里允许「免二次验证」：proof 与 waiver 两者必有其一（CHECK），waiver 只在
--   （1）操作者此刻没有已激活的 MFA 凭据，且（2）同一事务里有一条恰好对应本次写入的
--   mfa.step_up.waive 成功审计（同一操作者/作用域/会话/request_id/audience/action/租户/
--   资源绑定摘要）时才被触发器接受；已启用 MFA 的操作者仍必须用真实证明，规则不变。
LOCK TABLE schema_migrations, billing_adjustment_requests, billing_adjustment_decisions,
    custom_role_revisions, custom_role_deactivations, custom_role_grants, custom_role_grant_revocations IN ACCESS EXCLUSIVE MODE;

DO $migration_615_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 614 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 614 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=614 AND
        migration_id='614_purchased_subscription_owner' AND
        checksum_sha256='c855e6ed37d12f5a3d88eaa4ad3b27f61318c74b83151e9734bc60b8ab8cb688' AND
        down_checksum_sha256='c9d46e86a6460c8cd2e843e047f21eeaad7d47cd3777710df52c8e5bdb9f23f1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.billing_adjustment_mfa_waived_615(uuid,uuid,uuid,text,text,uuid,bytea)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 615 requires the exact verified 614 release head' USING ERRCODE='P6150';
    END IF;
END;
$migration_615_up$;

ALTER TABLE billing_adjustment_requests
    ADD COLUMN proposed_step_up_waived boolean NOT NULL DEFAULT false,
    ALTER COLUMN proposed_step_up_proof_id DROP NOT NULL,
    ALTER COLUMN proposed_step_up_use_ordinal DROP NOT NULL,
    ADD CONSTRAINT billing_adjustment_requests_step_up_authority_615 CHECK (
        (NOT proposed_step_up_waived AND proposed_step_up_proof_id IS NOT NULL
            AND proposed_step_up_use_ordinal = 1)
        OR
        (proposed_step_up_waived AND proposed_step_up_proof_id IS NULL
            AND proposed_step_up_use_ordinal IS NULL)
    );

ALTER TABLE billing_adjustment_decisions
    ADD COLUMN approved_step_up_waived boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT billing_adjustment_decisions_check,
    ADD CONSTRAINT billing_adjustment_decisions_step_up_authority_615 CHECK (
        (decision IN ('approved','rejected') AND step_up_binding_digest IS NOT NULL AND (
            (NOT approved_step_up_waived AND approved_step_up_proof_id IS NOT NULL
                AND approved_step_up_use_ordinal = 1)
            OR
            (approved_step_up_waived AND approved_step_up_proof_id IS NULL
                AND approved_step_up_use_ordinal IS NULL)))
        OR
        (decision = 'cancelled' AND step_up_binding_digest IS NULL AND NOT approved_step_up_waived
            AND approved_step_up_proof_id IS NULL AND approved_step_up_use_ordinal IS NULL)
    );

-- 自定义角色写入（rbacmanager）的 step-up 证据：操作者未启用 MFA 时方法记 'none'，
-- proof id 是 mfa.step_up.waive 审计资源 ID（这些表的 proof id 本来就没有外键）。
ALTER TABLE custom_role_revisions
    DROP CONSTRAINT custom_role_revisions_step_up_method_check,
    ADD CONSTRAINT custom_role_revisions_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn', 'none'));
ALTER TABLE custom_role_deactivations
    DROP CONSTRAINT custom_role_deactivations_step_up_method_check,
    ADD CONSTRAINT custom_role_deactivations_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn', 'none'));
ALTER TABLE custom_role_grants
    DROP CONSTRAINT custom_role_grants_step_up_method_check,
    ADD CONSTRAINT custom_role_grants_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn', 'none'));
ALTER TABLE custom_role_grant_revocations
    DROP CONSTRAINT custom_role_grant_revocations_step_up_method_check,
    ADD CONSTRAINT custom_role_grant_revocations_step_up_method_check
        CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn', 'none'));

-- The waiver authority: the actor has no active MFA credential in its scope
-- (same rule as mfa.hasActiveCredential) and exactly one successful
-- mfa.step_up.waive audit for this very write exists.
CREATE FUNCTION billing_adjustment_mfa_waived_615(
    actor_user uuid, actor_scope uuid, actor_session uuid, write_request_id text,
    step_up_action text, target_tenant uuid, binding bytea
) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT NOT EXISTS (
        SELECT 1 FROM mfa_credentials credential
        WHERE credential.user_id=actor_user AND credential.scope_id=actor_scope
          AND EXISTS (SELECT 1 FROM mfa_credential_events event
                      WHERE event.credential_id=credential.id AND event.event_type='activated')
          AND NOT EXISTS (SELECT 1 FROM mfa_credential_events event
                          WHERE event.credential_id=credential.id AND event.event_type IN ('disabled','reset'))
    ) AND (
        SELECT count(*) FROM audit_events audit
        WHERE audit.scope_id=actor_scope AND audit.actor_user_id=actor_user
          AND audit.action='mfa.step_up.waive' AND audit.result='success'
          AND audit.resource_type='mfa' AND audit.request_id=write_request_id
          AND audit.payload->>'session_id'=actor_session::text
          AND audit.payload->>'audience'='billing-adjustments'
          AND audit.payload->>'requested_action'=step_up_action
          AND audit.payload->>'tenant_id'=target_tenant::text
          AND audit.payload->>'step_up_note'='操作者未启用 MFA'
          AND binding IS NOT NULL
          AND audit.payload->>'resource_binding_sha256'=encode(binding,'hex')
    ) = 1
$$;

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
    IF NEW.proposed_step_up_waived THEN
        IF NEW.proposed_step_up_proof_id IS NOT NULL OR NOT billing_adjustment_mfa_waived_615(
            NEW.proposed_by_user_id, NEW.proposed_by_scope_id, NEW.proposed_by_session_id, NEW.request_id,
            'billing.adjustment.propose', NEW.target_tenant_id, NEW.step_up_binding_digest) THEN
            RAISE EXCEPTION 'billing adjustment proposal MFA waiver requires an operator without active MFA and its exact waiver audit'
                USING ERRCODE='P1002';
        END IF;
        RETURN NEW;
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

-- 435 version plus the waiver branch; the maker-checker / platform-admin
-- self-approval rule (435) is unchanged and applies before either authority.
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
    IF NEW.approved_step_up_waived THEN
        IF NEW.approved_step_up_proof_id IS NOT NULL OR NOT billing_adjustment_mfa_waived_615(
            NEW.approved_by_user_id, NEW.approved_by_scope_id, NEW.approved_by_session_id, NEW.request_id,
            'billing.adjustment.'||(CASE NEW.decision WHEN 'approved' THEN 'approve' ELSE 'reject' END),
            request.target_tenant_id, NEW.step_up_binding_digest) THEN
            RAISE EXCEPTION 'billing adjustment decision MFA waiver requires an operator without active MFA and its exact waiver audit'
                USING ERRCODE='P1002';
        END IF;
        RETURN NEW;
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

REVOKE ALL ON FUNCTION billing_adjustment_mfa_waived_615(uuid,uuid,uuid,text,text,uuid,bytea) FROM PUBLIC;
DO $$
BEGIN
    IF to_regrole('cdnca_control_app') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION billing_adjustment_mfa_waived_615(uuid,uuid,uuid,text,text,uuid,bytea)
            TO cdnca_control_app;
    END IF;
END;
$$;
