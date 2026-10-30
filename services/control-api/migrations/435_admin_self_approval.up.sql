LOCK TABLE schema_migrations, billing_adjustment_decisions, recharge_payment_approval_decisions_v1,
    high_risk_operations IN ACCESS EXCLUSIVE MODE;

DO $migration_435_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 434 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 434 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=434 AND
        migration_id='434_node_certificate_recovery' AND
        checksum_sha256='9213fec1fc5f7be37590c698594ddf787fbdcf2d870f042025eb897832e58b81' AND
        down_checksum_sha256='ae56e51e2cf3bb831ff4f7206423dced4ff93de0027daeacdcc66171df9b5a45' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.control_platform_admin_435(uuid,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 435 requires the exact verified 434 release head' USING ERRCODE='P4350';
    END IF;
END;
$migration_435_up$;

-- 435 (r136 admin-supreme; placeholder number, renumbered on merge). The
-- platform administrator is the highest authority (USER-DECISIONS 10-21
-- 04:15): every "approver must differ from proposer" rule lets a holder of
-- platform.admin decide its own request. The application records such a
-- decision with self_approved=true in the audit payload. Everyone else keeps
-- the maker-checker rule, enforced here as before.
CREATE FUNCTION control_platform_admin_435(subject_user_id uuid, subject_scope_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS(
        SELECT 1 FROM users account
        JOIN memberships membership ON membership.user_id=account.id AND membership.status='active'
        JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='platform'
        JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id
            AND assignment.user_id=account.id
        JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
            AND grant_row.permission_name='platform.admin'
        WHERE account.id=subject_user_id AND account.status='active'
          AND (subject_scope_id IS NULL OR membership.scope_id=subject_scope_id))
$$;
-- Callable by the application role: the trigger functions run as invoker.

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

CREATE OR REPLACE FUNCTION validate_recharge_payment_approval_171()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    request recharge_payment_approval_requests_v1%ROWTYPE;
    decision recharge_payment_approval_decisions_v1%ROWTYPE;
    order_scope uuid;
    order_revision bigint;
    order_state text;
    captured bigint;
    refunded bigint;
BEGIN
    IF TG_TABLE_NAME='recharge_payment_approval_requests_v1' THEN
        IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.proposed_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval proposer must belong to the platform scope' USING ERRCODE='P1711';
        END IF;
        SELECT tenant_scope_id,revision,state,captured_minor,refunded_minor
        INTO order_scope,order_revision,order_state,captured,refunded
        FROM recharge_orders_v1 WHERE id=NEW.order_id FOR SHARE;
        IF order_scope IS NULL OR order_scope<>NEW.tenant_scope_id OR order_revision<>NEW.expected_order_revision OR
           order_state NOT IN ('paid','partially_refunded') OR captured<=0 OR NEW.amount_minor>captured-refunded THEN
            RAISE EXCEPTION 'approval proposal does not match the live recharge order' USING ERRCODE='P1712';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_decisions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        IF request.id IS NULL OR (NEW.decided_by_user_id=request.proposed_by_user_id AND
           NOT control_platform_admin_435(NEW.decided_by_user_id,NEW.decided_by_scope_id)) OR
           NEW.decided_at>=request.expires_at OR
           NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.decided_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval decision violates maker-checker or expiry' USING ERRCODE='P1713';
        END IF;
        IF EXISTS(SELECT 1 FROM recharge_payment_approval_decisions_v1 WHERE approval_request_id=request.id) THEN
            RAISE EXCEPTION 'approval request already has a decision' USING ERRCODE='P1714';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_executions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        SELECT * INTO decision FROM recharge_payment_approval_decisions_v1
        WHERE approval_request_id=NEW.approval_request_id AND decision='approved' FOR SHARE;
        IF request.id IS NULL OR decision.id IS NULL OR NEW.authorized_at>=request.expires_at OR
           (NEW.actor_scope_id,NEW.actor_user_id,NEW.actor_session_id) IS DISTINCT FROM
           (decision.decided_by_scope_id,decision.decided_by_user_id,decision.decided_by_session_id) THEN
            RAISE EXCEPTION 'approval execution is not bound to the approved checker' USING ERRCODE='P1715';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_high_risk_operation_183()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent high_risk_operations%ROWTYPE;
    job_kind text;
    proposer_scope_id uuid;
    approver_scope_id uuid;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'high-risk operations cannot be deleted' USING ERRCODE='P1831';
    END IF;

    IF TG_OP='INSERT' THEN
        IF NEW.state<>'pending_approval' OR NEW.revision<>1 OR NEW.updated_at<>NEW.created_at OR
           NEW.approved_by IS NOT NULL OR NEW.job_id IS NOT NULL OR
           NEW.approval_base_revision<>0 OR NEW.approval_idempotency_key IS NOT NULL OR
           NEW.execution_request_id IS NOT NULL OR NEW.execution_digest IS NOT NULL OR NEW.failure_code IS NOT NULL THEN
            RAISE EXCEPTION 'high-risk operation proposals must start pending at revision 1' USING ERRCODE='P1832';
        END IF;
        SELECT m.scope_id INTO proposer_scope_id
        FROM memberships m JOIN access_scopes s ON s.id=m.scope_id
        WHERE m.user_id=NEW.proposed_by AND m.status='active' AND s.kind='platform'
        ORDER BY m.scope_id LIMIT 1;
        NEW.proposed_by_scope_id := proposer_scope_id;
        IF proposer_scope_id IS NULL THEN
            RAISE EXCEPTION 'high-risk operation proposer must have an active scope membership' USING ERRCODE='P1833';
        END IF;
    ELSE
        IF ROW(NEW.id,NEW.tenant_id,NEW.scope_id,NEW.target_id,NEW.kind,NEW.mode,
               NEW.parent_operation_id,NEW.execution_ref_kind,NEW.execution_ref_id,
               NEW.execution_ref_revision,NEW.recovery_ref_kind,NEW.recovery_ref_id,
               NEW.recovery_ref_revision,NEW.reason,NEW.preflight_target_revision,
               NEW.execution_sha256,NEW.recovery_sha256,NEW.health_contract_sha256,
               NEW.rollback_required,NEW.preflight_expires_at,NEW.proposed_by,
               NEW.proposed_by_scope_id,NEW.proposal_idempotency_key,NEW.proposal_digest,
               NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id,OLD.tenant_id,OLD.scope_id,OLD.target_id,OLD.kind,OLD.mode,
               OLD.parent_operation_id,OLD.execution_ref_kind,OLD.execution_ref_id,
               OLD.execution_ref_revision,OLD.recovery_ref_kind,OLD.recovery_ref_id,
               OLD.recovery_ref_revision,OLD.reason,OLD.preflight_target_revision,
               OLD.execution_sha256,OLD.recovery_sha256,OLD.health_contract_sha256,
               OLD.rollback_required,OLD.preflight_expires_at,OLD.proposed_by,
               OLD.proposed_by_scope_id,OLD.proposal_idempotency_key,OLD.proposal_digest,
               OLD.created_at) OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at THEN
            RAISE EXCEPTION 'high-risk operation proposal facts and revision are immutable' USING ERRCODE='P1834';
        END IF;
        IF OLD.state IN ('succeeded','failed','rejected') THEN
            RAISE EXCEPTION 'terminal high-risk operations cannot be modified' USING ERRCODE='P1835';
        END IF;
        IF OLD.state='pending_approval' AND NEW.state IN ('queued','rejected') THEN
            IF NEW.approved_by IS NULL OR (NEW.approved_by=NEW.proposed_by AND
               NOT control_platform_admin_435(NEW.approved_by,NULL)) OR
               NEW.approval_base_revision<>OLD.revision OR NEW.approval_idempotency_key IS NULL THEN
                RAISE EXCEPTION 'high-risk approval requires a different active scope member' USING ERRCODE='P1836';
            END IF;
            SELECT m.scope_id INTO approver_scope_id
            FROM memberships m JOIN access_scopes s ON s.id=m.scope_id
            WHERE m.user_id=NEW.approved_by AND m.status='active' AND s.kind='platform'
            ORDER BY m.scope_id LIMIT 1;
            NEW.approved_by_scope_id := approver_scope_id;
            IF approver_scope_id IS NULL THEN
                RAISE EXCEPTION 'high-risk operation approver must have an active scope membership' USING ERRCODE='P1837';
            END IF;
            IF NEW.state='queued' THEN
                SELECT kind INTO job_kind FROM background_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
                IF NEW.job_id IS NULL OR job_kind IS DISTINCT FROM 'system.high_risk_operation.v1' THEN
                    RAISE EXCEPTION 'queued high-risk operations require their typed background job' USING ERRCODE='P1838';
                END IF;
            END IF;
        ELSIF OLD.state='queued' AND NEW.state IN ('succeeded','failed') THEN
            IF ROW(NEW.approved_by,NEW.approved_by_scope_id,NEW.job_id,NEW.approval_base_revision,
                   NEW.approval_idempotency_key) IS DISTINCT FROM
               ROW(OLD.approved_by,OLD.approved_by_scope_id,OLD.job_id,OLD.approval_base_revision,
                   OLD.approval_idempotency_key) THEN
                RAISE EXCEPTION 'high-risk approval facts cannot change after queueing' USING ERRCODE='P1845';
            END IF;
            IF NEW.approved_by IS NULL OR NEW.job_id IS NULL OR NEW.execution_request_id IS NULL OR
               NEW.execution_digest IS NULL OR NOT EXISTS (
                SELECT 1 FROM high_risk_operation_receipts receipt
                WHERE receipt.operation_id=NEW.id AND receipt.scope_id=NEW.scope_id AND
                      receipt.request_id=NEW.execution_request_id AND receipt.receipt_digest=NEW.execution_digest AND
                      receipt.state=NEW.state
            ) THEN
                RAISE EXCEPTION 'terminal high-risk execution requires a matching immutable receipt' USING ERRCODE='P1839';
            END IF;
            IF NEW.state='succeeded' AND NEW.failure_code IS NOT NULL THEN
                RAISE EXCEPTION 'successful high-risk execution cannot carry a failure code' USING ERRCODE='P1840';
            END IF;
            IF NEW.state='failed' AND (NEW.failure_code IS NULL OR
               NEW.failure_code !~ '^[a-z][a-z0-9._-]{0,127}$') THEN
                RAISE EXCEPTION 'failed high-risk execution requires a stable failure code' USING ERRCODE='P1841';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid high-risk operation state transition' USING ERRCODE='P1842';
        END IF;
    END IF;

    IF NEW.mode='rollback' THEN
        SELECT * INTO parent FROM high_risk_operations WHERE id=NEW.parent_operation_id AND scope_id=NEW.scope_id;
        IF NOT FOUND OR parent.target_id<>NEW.target_id OR parent.kind<>NEW.kind OR
           NEW.execution_ref_kind<>parent.recovery_ref_kind OR NEW.execution_ref_id<>parent.recovery_ref_id OR
           NEW.execution_ref_revision<>parent.recovery_ref_revision OR NEW.recovery_ref_kind<>parent.execution_ref_kind OR
           NEW.recovery_ref_id<>parent.execution_ref_id OR NEW.recovery_ref_revision<>parent.execution_ref_revision THEN
            RAISE EXCEPTION 'rollback operation must reverse the same scoped parent references' USING ERRCODE='P1843';
        END IF;
    ELSIF NEW.parent_operation_id IS NOT NULL THEN
        RAISE EXCEPTION 'apply operation cannot have a parent' USING ERRCODE='P1844';
    END IF;
    RETURN NEW;
END;
$$;
