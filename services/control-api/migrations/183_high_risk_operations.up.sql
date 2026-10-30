LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,
    access_scopes,memberships,background_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_183$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>182 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>182 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=182 AND migration_id='182_node_isolation' AND
              checksum_sha256='bfc432e0cdf91e7f0d666c0229b98dee466ee26c729f4c98b77166b0cc4cd962' AND
              down_checksum_sha256='3f7b6dedf1749eae0f699e616731604f4a31609c36097def4ffbbeae21d58a27' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.high_risk_operations') IS NOT NULL OR
         to_regclass(current_schema() || '.high_risk_operation_receipts') IS NOT NULL OR
         to_regprocedure(current_schema() || '.protect_high_risk_operation_183()') IS NOT NULL OR
         to_regprocedure(current_schema() || '.reject_high_risk_operation_receipt_mutation_183()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 183 requires the exact verified 182 release head and an untouched high-risk operation schema'
            USING ERRCODE='P1830';
    END IF;
END;
$migration_183$;

INSERT INTO permissions(name,description) VALUES
    ('system_operations.manage','Propose and approve high-risk system operations'),
    ('system_operations.execute','Execute queued high-risk system operations and record receipts');
INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required) VALUES
    ('system_operations.manage',true),
    ('system_operations.execute',false);
INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'system_operations.manage'
FROM roles role JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
WHERE role.system_role AND role.name='platform_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_high_risk_operation_permission_183()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name='platform_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='platform'
    ) THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'system_operations.manage') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER roles_high_risk_operation_permission_183
AFTER INSERT ON roles FOR EACH ROW EXECUTE FUNCTION grant_high_risk_operation_permission_183();

CREATE TABLE high_risk_operations (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL,
    target_id uuid NOT NULL CHECK(target_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    kind text NOT NULL CHECK(kind IN (
        'default_credential_remediation','managed_password_reset','node_reregister',
        'control_endpoint_change','disk_cleanup','backup','restore','uninstall','site_script_removal'
    )),
    mode text NOT NULL CHECK(mode IN ('apply','rollback')),
    parent_operation_id uuid,
    execution_ref_kind text NOT NULL CHECK(execution_ref_kind IN (
        'credential_rotation','credential_recovery','password_reset','node_identity_rotation',
        'node_port_transition','disk_cleanup_plan','control_backup','control_restore',
        'control_upgrade','edge_publication','health_evidence'
    )),
    execution_ref_id uuid NOT NULL CHECK(execution_ref_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    execution_ref_revision bigint NOT NULL CHECK(execution_ref_revision>0),
    recovery_ref_kind text NOT NULL CHECK(recovery_ref_kind IN (
        'credential_rotation','credential_recovery','password_reset','node_identity_rotation',
        'node_port_transition','disk_cleanup_plan','control_backup','control_restore',
        'control_upgrade','edge_publication','health_evidence'
    )),
    recovery_ref_id uuid NOT NULL CHECK(recovery_ref_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    recovery_ref_revision bigint NOT NULL CHECK(recovery_ref_revision>0),
    reason text NOT NULL CHECK(
        char_length(reason) BETWEEN 1 AND 512 AND reason=btrim(reason) AND
        reason !~ '[[:cntrl:]]' AND position(U&'\2028' in reason)=0 AND position(U&'\2029' in reason)=0
    ),
    preflight_target_revision bigint NOT NULL CHECK(preflight_target_revision>0),
    execution_sha256 bytea NOT NULL CHECK(octet_length(execution_sha256)=32),
    recovery_sha256 bytea NOT NULL CHECK(octet_length(recovery_sha256)=32),
    health_contract_sha256 bytea NOT NULL CHECK(octet_length(health_contract_sha256)=32),
    rollback_required boolean NOT NULL,
    preflight_expires_at timestamptz NOT NULL CHECK(isfinite(preflight_expires_at)),
    state text NOT NULL CHECK(state IN ('pending_approval','queued','succeeded','failed','rejected')),
    proposed_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    proposed_by_scope_id uuid,
    approved_by uuid REFERENCES users(id) ON DELETE RESTRICT,
    approved_by_scope_id uuid,
    job_id uuid,
    approval_base_revision bigint NOT NULL DEFAULT 0 CHECK(approval_base_revision>=0),
    approval_idempotency_key text CHECK(approval_idempotency_key IS NULL OR
        approval_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    execution_request_id text CHECK(execution_request_id IS NULL OR
        execution_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    execution_digest bytea CHECK(execution_digest IS NULL OR octet_length(execution_digest)=32),
    failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    revision bigint NOT NULL CHECK(revision>0),
    proposal_idempotency_key text NOT NULL CHECK(
        proposal_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    proposal_digest bytea NOT NULL CHECK(octet_length(proposal_digest)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at)),
    UNIQUE(scope_id,id),
    UNIQUE(scope_id,proposal_idempotency_key),
    UNIQUE(scope_id,execution_request_id),
    FOREIGN KEY(scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,parent_operation_id) REFERENCES high_risk_operations(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(proposed_by_scope_id,proposed_by) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(approved_by_scope_id,approved_by) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK(updated_at>=created_at),
    CHECK((mode='apply' AND parent_operation_id IS NULL) OR
          (mode='rollback' AND parent_operation_id IS NOT NULL)),
    CHECK((state='pending_approval' AND approved_by IS NULL AND approved_by_scope_id IS NULL AND
           job_id IS NULL AND approval_base_revision=0 AND approval_idempotency_key IS NULL AND
           execution_request_id IS NULL AND execution_digest IS NULL AND failure_code IS NULL) OR
          (state='queued' AND approved_by IS NOT NULL AND approved_by_scope_id IS NOT NULL AND
           job_id IS NOT NULL AND approval_base_revision>0 AND approval_idempotency_key IS NOT NULL AND
           execution_request_id IS NULL AND execution_digest IS NULL AND failure_code IS NULL) OR
          (state='rejected' AND approved_by IS NOT NULL AND approved_by_scope_id IS NOT NULL AND
           job_id IS NULL AND approval_base_revision>0 AND approval_idempotency_key IS NOT NULL AND
           execution_request_id IS NULL AND execution_digest IS NULL AND failure_code IS NULL) OR
          (state='succeeded' AND approved_by IS NOT NULL AND approved_by_scope_id IS NOT NULL AND
           job_id IS NOT NULL AND approval_base_revision>0 AND approval_idempotency_key IS NOT NULL AND
           execution_request_id IS NOT NULL AND execution_digest IS NOT NULL AND failure_code IS NULL) OR
          (state='failed' AND approved_by IS NOT NULL AND approved_by_scope_id IS NOT NULL AND
           job_id IS NOT NULL AND approval_base_revision>0 AND approval_idempotency_key IS NOT NULL AND
           execution_request_id IS NOT NULL AND execution_digest IS NOT NULL AND failure_code IS NOT NULL))
);

CREATE INDEX high_risk_operations_scope_created_183_idx
    ON high_risk_operations(scope_id,created_at DESC,id DESC);
CREATE INDEX high_risk_operations_scope_state_183_idx
    ON high_risk_operations(scope_id,state,created_at DESC,id DESC);

CREATE TABLE high_risk_operation_receipts (
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    receipt_digest bytea NOT NULL CHECK(octet_length(receipt_digest)=32),
    receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
    state text NOT NULL CHECK(state IN ('succeeded','failed')),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at)),
    PRIMARY KEY(operation_id,request_id),
    UNIQUE(scope_id,operation_id,request_id),
    FOREIGN KEY(scope_id,operation_id) REFERENCES high_risk_operations(scope_id,id) ON DELETE RESTRICT
);

CREATE INDEX high_risk_operation_receipts_scope_recorded_183_idx
    ON high_risk_operation_receipts(scope_id,recorded_at DESC,operation_id,request_id);

CREATE FUNCTION validate_high_risk_operation_receipt_183()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    operation_state text;
BEGIN
    SELECT state INTO operation_state
    FROM high_risk_operations
    WHERE id=NEW.operation_id AND scope_id=NEW.scope_id;
    IF operation_state IS DISTINCT FROM 'queued' THEN
        RAISE EXCEPTION 'high-risk operation receipts require a queued parent operation' USING ERRCODE='P1847';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER high_risk_operation_receipts_validate_183
BEFORE INSERT ON high_risk_operation_receipts
FOR EACH ROW EXECUTE FUNCTION validate_high_risk_operation_receipt_183();

CREATE FUNCTION protect_high_risk_operation_183()
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
            IF NEW.approved_by IS NULL OR NEW.approved_by=NEW.proposed_by OR
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

CREATE TRIGGER high_risk_operations_guard_183
BEFORE INSERT OR UPDATE OR DELETE ON high_risk_operations
FOR EACH ROW EXECUTE FUNCTION protect_high_risk_operation_183();

CREATE FUNCTION reject_high_risk_operation_truncate_183()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'high-risk operations cannot be truncated' USING ERRCODE='P1845';
END;
$$;
CREATE TRIGGER high_risk_operations_no_truncate_183
BEFORE TRUNCATE ON high_risk_operations
FOR EACH STATEMENT EXECUTE FUNCTION reject_high_risk_operation_truncate_183();

CREATE FUNCTION reject_high_risk_operation_receipt_mutation_183()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'high-risk operation receipts are append-only' USING ERRCODE='P1846';
END;
$$;
CREATE TRIGGER high_risk_operation_receipts_append_only_183
BEFORE UPDATE OR DELETE ON high_risk_operation_receipts
FOR EACH ROW EXECUTE FUNCTION reject_high_risk_operation_receipt_mutation_183();
CREATE TRIGGER high_risk_operation_receipts_no_truncate_183
BEFORE TRUNCATE ON high_risk_operation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION reject_high_risk_operation_receipt_mutation_183();

REVOKE ALL ON high_risk_operations,high_risk_operation_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_high_risk_operation_permission_183() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_high_risk_operation_receipt_183() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_high_risk_operation_183() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_high_risk_operation_truncate_183() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_high_risk_operation_receipt_mutation_183() FROM PUBLIC;
