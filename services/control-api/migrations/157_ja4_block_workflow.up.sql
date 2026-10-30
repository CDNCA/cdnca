LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_157$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>156 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>156 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=156 AND migration_id='156_runtime_patch_policy' AND
              checksum_sha256='34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788' AND
              down_checksum_sha256='a29ada54fad54860ca7da7f200bd99cd95132e91e4015d5ebfaf5835f215d495' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('ja4_block_workflows_157') IS NOT NULL OR
         to_regclass('ja4_block_outbox_157') IS NOT NULL OR
         to_regclass('ja4_block_receipts_157') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 157 requires a contiguous verified 156 release head'
            USING ERRCODE='P1570';
    END IF;
END;
$migration_157$;

CREATE TABLE ja4_block_workflows_157 (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_scope_kind text NOT NULL CHECK(actor_scope_kind IN ('platform','tenant')),
    session_id uuid NOT NULL,
    step_up_evidence_id uuid NOT NULL,
    step_up_verified_at timestamptz NOT NULL CHECK(isfinite(step_up_verified_at)),
    ja4_sha256 bytea NOT NULL CHECK(octet_length(ja4_sha256)=32),
    ranking_snapshot_at timestamptz NOT NULL CHECK(isfinite(ranking_snapshot_at)),
    ranking_expires_at timestamptz NOT NULL CHECK(isfinite(ranking_expires_at) AND ranking_expires_at>ranking_snapshot_at),
    duration_seconds bigint NOT NULL CHECK(duration_seconds BETWEEN 60 AND 2592000),
    reason text NOT NULL CHECK(reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    phase text NOT NULL CHECK(phase IN ('queued','policy_ready','edge_pending','active','failed','expired')),
    revision bigint NOT NULL CHECK(revision>0),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_bytes bytea NOT NULL CHECK(octet_length(request_bytes) BETWEEN 1 AND 262144),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    workflow_json jsonb NOT NULL CHECK(jsonb_typeof(workflow_json)='object'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(tenant_scope_id,idempotency_key),
    FOREIGN KEY(tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    CHECK(request_sha256=sha256(request_bytes))
);

CREATE TABLE ja4_block_outbox_157 (
    workflow_id uuid NOT NULL REFERENCES ja4_block_workflows_157(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK(action IN ('apply_policy','publish_binding')),
    state text NOT NULL CHECK(state IN ('pending','claimed','completed')),
    attempt_count integer NOT NULL CHECK(attempt_count BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    claimed_by text CHECK(claimed_by IS NULL OR claimed_by ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    claim_token uuid,
    claim_expires_at timestamptz CHECK(claim_expires_at IS NULL OR isfinite(claim_expires_at)),
    last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY(workflow_id,action),
    CHECK((state='claimed')=(claimed_by IS NOT NULL AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
    CHECK(state='claimed' OR (claimed_by IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL))
);

CREATE TABLE ja4_block_receipts_157 (
    id uuid PRIMARY KEY,
    workflow_id uuid NOT NULL REFERENCES ja4_block_workflows_157(id) ON DELETE RESTRICT,
    receipt_kind text NOT NULL CHECK(receipt_kind IN ('policy','binding','edge')),
    phase_revision bigint NOT NULL CHECK(phase_revision>1),
    external_id uuid NOT NULL,
    receipt_bytes bytea NOT NULL CHECK(octet_length(receipt_bytes) BETWEEN 1 AND 262144),
    receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    UNIQUE(workflow_id,receipt_kind,phase_revision),
    CHECK(receipt_sha256=sha256(receipt_bytes))
);

CREATE FUNCTION guard_ja4_block_workflow_157()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR NEW.actor_scope_kind IS DISTINCT FROM OLD.actor_scope_kind OR
       NEW.session_id IS DISTINCT FROM OLD.session_id OR NEW.step_up_evidence_id IS DISTINCT FROM OLD.step_up_evidence_id OR
       NEW.step_up_verified_at IS DISTINCT FROM OLD.step_up_verified_at OR
       NEW.ja4_sha256 IS DISTINCT FROM OLD.ja4_sha256 OR NEW.ranking_snapshot_at IS DISTINCT FROM OLD.ranking_snapshot_at OR
       NEW.ranking_expires_at IS DISTINCT FROM OLD.ranking_expires_at OR NEW.duration_seconds IS DISTINCT FROM OLD.duration_seconds OR
       NEW.reason IS DISTINCT FROM OLD.reason OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.request_bytes IS DISTINCT FROM OLD.request_bytes OR
       NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       (NEW.workflow_json-ARRAY['Phase','Revision','PolicyID','PolicyRevision','BindingID','BindingRevision',
          'PublicationID','EdgeState','AttemptCount','LastErrorCode','AvailableAt','UpdatedAt','Replayed']::text[])
         IS DISTINCT FROM
       (OLD.workflow_json-ARRAY['Phase','Revision','PolicyID','PolicyRevision','BindingID','BindingRevision',
          'PublicationID','EdgeState','AttemptCount','LastErrorCode','AvailableAt','UpdatedAt','Replayed']::text[]) OR
       NEW.revision<OLD.revision OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'JA4 block workflow identity or revision mutation rejected' USING ERRCODE='P1571';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_ja4_block_receipt_157()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'JA4 block receipts are immutable' USING ERRCODE='P1571';
END;
$$;

CREATE FUNCTION prevent_ja4_block_truncate_157()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'JA4 block workflow facts cannot be truncated' USING ERRCODE='P1571';
END;
$$;

CREATE TRIGGER ja4_block_workflow_guard_157
BEFORE UPDATE OR DELETE ON ja4_block_workflows_157
FOR EACH ROW EXECUTE FUNCTION guard_ja4_block_workflow_157();

CREATE TRIGGER ja4_block_receipt_guard_157
BEFORE UPDATE OR DELETE ON ja4_block_receipts_157
FOR EACH ROW EXECUTE FUNCTION guard_ja4_block_receipt_157();

CREATE TRIGGER ja4_block_workflow_truncate_157
BEFORE TRUNCATE ON ja4_block_workflows_157
FOR EACH STATEMENT EXECUTE FUNCTION prevent_ja4_block_truncate_157();

CREATE TRIGGER ja4_block_outbox_truncate_157
BEFORE TRUNCATE ON ja4_block_outbox_157
FOR EACH STATEMENT EXECUTE FUNCTION prevent_ja4_block_truncate_157();

CREATE TRIGGER ja4_block_receipt_truncate_157
BEFORE TRUNCATE ON ja4_block_receipts_157
FOR EACH STATEMENT EXECUTE FUNCTION prevent_ja4_block_truncate_157();

REVOKE ALL ON ja4_block_workflows_157 FROM PUBLIC;
REVOKE ALL ON ja4_block_outbox_157 FROM PUBLIC;
REVOKE ALL ON ja4_block_receipts_157 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_ja4_block_workflow_157() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_ja4_block_receipt_157() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_ja4_block_truncate_157() FROM PUBLIC;
