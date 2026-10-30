LOCK TABLE schema_migrations,firewall_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_158$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>157 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>157 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=157 AND migration_id='157_ja4_block_workflow' AND
              checksum_sha256='d6f9a03fcdc4cd47fe62fe861c8f57e3f25f11fe9bfa9abbb1db2732f411e104' AND
              down_checksum_sha256='0f31778af185f8505b528ba938fadb7655bbad43690c3a9790632b531ec6720c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('ja4_block_edge_receipt_queue_158') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 158 requires a contiguous verified 157 release head'
            USING ERRCODE='P1580';
    END IF;
END;
$migration_158$;

CREATE TABLE ja4_block_edge_receipt_queue_158 (
    receipt_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL,
    workflow_id uuid NOT NULL REFERENCES ja4_block_workflows_157(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK(policy_revision>0),
    binding_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK(binding_revision>0),
    publication_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    node_id uuid NOT NULL,
    config_sha256 bytea NOT NULL CHECK(octet_length(config_sha256)=32),
    receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
    expected_revision bigint NOT NULL CHECK(expected_revision>0),
    active_policy_revision bigint NOT NULL CHECK(active_policy_revision>=0),
    terminal_state text NOT NULL CHECK(terminal_state IN ('active','failed','rolled_back')),
    reason_code text NOT NULL CHECK(reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_scope_kind text NOT NULL CHECK(actor_scope_kind IN ('platform','tenant')),
    session_id uuid NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','claimed','completed','rejected')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    claimed_by text CHECK(claimed_by IS NULL OR claimed_by ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    claim_token uuid,
    claim_expires_at timestamptz CHECK(claim_expires_at IS NULL OR isfinite(claim_expires_at)),
    last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
    recorded_at timestamptz CHECK(recorded_at IS NULL OR isfinite(recorded_at)),
    completed_at timestamptz CHECK(completed_at IS NULL OR isfinite(completed_at)),
    rejected_at timestamptz CHECK(rejected_at IS NULL OR isfinite(rejected_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(workflow_id,node_id),
    UNIQUE(publication_id,node_id),
    FOREIGN KEY(tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,node_id) REFERENCES nodes(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,publication_id,binding_id)
        REFERENCES security_policy_publications(tenant_scope_id,id,binding_id) ON DELETE RESTRICT,
    FOREIGN KEY(session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    CHECK((state='claimed')=(claimed_by IS NOT NULL AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
    CHECK(state='claimed' OR (claimed_by IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL)),
    CHECK((state='completed')=(completed_at IS NOT NULL)),
    CHECK((state='rejected')=(rejected_at IS NOT NULL)),
    CHECK(completed_at IS NULL OR recorded_at IS NOT NULL),
    CHECK(recorded_at IS NULL OR recorded_at>=observed_at),
    CHECK(completed_at IS NULL OR completed_at>=recorded_at),
    CHECK(rejected_at IS NULL OR rejected_at>=observed_at)
);

CREATE INDEX ja4_block_edge_receipt_queue_ready_158_idx
    ON ja4_block_edge_receipt_queue_158(available_at,receipt_id)
    WHERE state IN ('pending','claimed');

CREATE FUNCTION enqueue_ja4_block_edge_receipt_158()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    workflow ja4_block_workflows_157%ROWTYPE;
    receipt_state text;
    receipt_reason text;
BEGIN
    IF NEW.state<>'acked' OR OLD.state='acked' OR NEW.policy_kind<>'waf' THEN
        RETURN NEW;
    END IF;
    SELECT * INTO workflow FROM ja4_block_workflows_157 candidate
    WHERE candidate.workflow_json->>'PublicationID'=NEW.publication_id::text
      AND NEW.policy_kind='waf'
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    IF workflow.tenant_scope_id<>NEW.tenant_scope_id OR workflow.site_id<>NEW.site_id OR
       workflow.phase<>'edge_pending' OR workflow.workflow_json->>'PolicyID'<>NEW.policy_id::text OR
       (workflow.workflow_json->>'PolicyRevision')::bigint<>NEW.policy_version OR
       workflow.workflow_json->>'BindingID'<>NEW.binding_id::text OR
       (workflow.workflow_json->>'BindingRevision')::bigint<1 OR
       workflow.workflow_json->>'RolloutID' IS NULL OR
       NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(workflow.workflow_json->'TargetNodeIDs') target(node_id)
                   WHERE target.node_id=NEW.node_id::text) OR
       NEW.terminal_state IS NULL OR NEW.active_policy_version IS NULL OR NEW.acked_at IS NULL OR
       NEW.last_error IS NULL OR NEW.last_error !~ '^ack-sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'JA4 edge receipt workflow or publication identity mismatch' USING ERRCODE='P1581';
    END IF;
    receipt_state := CASE NEW.terminal_state WHEN 'applied' THEN 'active'
        WHEN 'failed' THEN 'failed' WHEN 'rolled_back' THEN 'rolled_back' END;
    IF receipt_state IS NULL OR
       (receipt_state='active' AND NEW.active_policy_version<>NEW.policy_version) OR
       (receipt_state<>'active' AND NEW.active_policy_version<>NEW.expected_active_policy_version) THEN
        RAISE EXCEPTION 'JA4 edge receipt terminal state mismatch' USING ERRCODE='P1581';
    END IF;
    receipt_reason := CASE receipt_state WHEN 'active' THEN 'edge_applied'
        WHEN 'rolled_back' THEN 'edge_rollback_confirmed' ELSE 'edge_failed' END;
    INSERT INTO ja4_block_edge_receipt_queue_158(
        receipt_id,tenant_scope_id,site_id,workflow_id,policy_id,policy_revision,
        binding_id,binding_revision,publication_id,rollout_id,node_id,config_sha256,receipt_sha256,
        expected_revision,active_policy_revision,terminal_state,reason_code,
        actor_user_id,actor_scope_id,actor_scope_kind,session_id,state,available_at,
        observed_at,created_at,updated_at)
    VALUES(NEW.id,NEW.tenant_scope_id,NEW.site_id,workflow.id,NEW.policy_id,NEW.policy_version,
        NEW.binding_id,(workflow.workflow_json->>'BindingRevision')::bigint,NEW.publication_id,
        (workflow.workflow_json->>'RolloutID')::uuid,NEW.node_id,NEW.command_sha256,
        decode(substr(NEW.last_error,12),'hex'),workflow.revision,NEW.active_policy_version,
        receipt_state,receipt_reason,workflow.actor_user_id,workflow.actor_scope_id,
        workflow.actor_scope_kind,workflow.session_id,'pending',NEW.acked_at,NEW.acked_at,NEW.acked_at,NEW.acked_at);
    RETURN NEW;
END;
$$;

CREATE TRIGGER ja4_block_edge_receipt_enqueue_158
AFTER UPDATE OF state ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION enqueue_ja4_block_edge_receipt_158();

CREATE FUNCTION guard_ja4_block_edge_receipt_158()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.receipt_id,NEW.tenant_scope_id,NEW.site_id,NEW.workflow_id,
       NEW.policy_id,NEW.policy_revision,NEW.binding_id,NEW.binding_revision,NEW.publication_id,
       NEW.rollout_id,NEW.node_id,NEW.config_sha256,NEW.receipt_sha256,NEW.expected_revision,
       NEW.active_policy_revision,NEW.terminal_state,NEW.reason_code,NEW.actor_user_id,
       NEW.actor_scope_id,NEW.actor_scope_kind,NEW.session_id,NEW.observed_at,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.receipt_id,OLD.tenant_scope_id,OLD.site_id,OLD.workflow_id,
       OLD.policy_id,OLD.policy_revision,OLD.binding_id,OLD.binding_revision,OLD.publication_id,
       OLD.rollout_id,OLD.node_id,OLD.config_sha256,OLD.receipt_sha256,OLD.expected_revision,
       OLD.active_policy_revision,OLD.terminal_state,OLD.reason_code,OLD.actor_user_id,
       OLD.actor_scope_id,OLD.actor_scope_kind,OLD.session_id,OLD.observed_at,OLD.created_at) OR
       NOT ((OLD.state='pending' AND NEW.state='claimed') OR
            (OLD.state='claimed' AND NEW.state IN ('claimed','pending','completed','rejected'))) OR
       NEW.attempt_count<OLD.attempt_count OR NEW.updated_at<OLD.updated_at OR
       OLD.recorded_at IS NOT NULL AND NEW.recorded_at IS DISTINCT FROM OLD.recorded_at OR
       OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at OR
       OLD.rejected_at IS NOT NULL AND NEW.rejected_at IS DISTINCT FROM OLD.rejected_at THEN
        RAISE EXCEPTION 'JA4 edge receipt identity or lifecycle mutation rejected' USING ERRCODE='P1581';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_ja4_block_edge_receipt_truncate_158()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'JA4 edge receipt facts cannot be truncated' USING ERRCODE='P1581';
END;
$$;

CREATE TRIGGER ja4_block_edge_receipt_guard_158
BEFORE UPDATE OR DELETE ON ja4_block_edge_receipt_queue_158
FOR EACH ROW EXECUTE FUNCTION guard_ja4_block_edge_receipt_158();

CREATE TRIGGER ja4_block_edge_receipt_truncate_158
BEFORE TRUNCATE ON ja4_block_edge_receipt_queue_158
FOR EACH STATEMENT EXECUTE FUNCTION prevent_ja4_block_edge_receipt_truncate_158();

REVOKE ALL ON ja4_block_edge_receipt_queue_158 FROM PUBLIC;
REVOKE ALL ON FUNCTION enqueue_ja4_block_edge_receipt_158() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_ja4_block_edge_receipt_158() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_ja4_block_edge_receipt_truncate_158() FROM PUBLIC;
