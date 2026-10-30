LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 92 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 92 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 92
          AND migration_id = '092_l4_package_runtime_contract'
          AND checksum_sha256 = '5b9d6ced167be563e6dfdbe022681b7ed6842728a831597389a3a4e9280d8c6d'
          AND down_checksum_sha256 = '8cd70b1cf78f3ea668934b6db898a2c0d1a487bc4a85f05dd9585d4a66058bbc'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 093 requires the exact verified 092 release head'
            USING ERRCODE = 'P9300';
    END IF;
END;
$$;

CREATE TABLE control_upgrade_rollout_plans (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    schema_version smallint NOT NULL,
    revision bigint NOT NULL,
    state text NOT NULL,
    resume_state text NOT NULL,
    completion text NOT NULL,
    active_batch integer NOT NULL,
    canonical_snapshot_bytes bytea NOT NULL,
    canonical_snapshot_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (id, actor_scope_id, actor_user_id, installation_id)
);

CREATE TABLE control_upgrade_rollout_events (
    plan_id uuid NOT NULL,
    revision bigint NOT NULL,
    event_id uuid NOT NULL UNIQUE,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    causation_id uuid NOT NULL,
    causation_bytes bytea NOT NULL,
    causation_sha256 bytea NOT NULL,
    event_bytes bytea NOT NULL,
    event_sha256 bytea NOT NULL,
    result_snapshot_bytes bytea NOT NULL,
    result_snapshot_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (plan_id, revision),
    UNIQUE (plan_id, causation_id),
    FOREIGN KEY (plan_id, actor_scope_id, actor_user_id, installation_id)
        REFERENCES control_upgrade_rollout_plans(id, actor_scope_id, actor_user_id, installation_id)
        ON DELETE RESTRICT
);

CREATE TABLE control_upgrade_node_commands (
    command_id uuid PRIMARY KEY,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL,
    batch_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    action text NOT NULL,
    signed_execution_bytes bytea NOT NULL,
    signed_execution_sha256 bytea NOT NULL,
    state text NOT NULL,
    created_at timestamptz NOT NULL,
    published_at timestamptz,
    acknowledged_at timestamptz,
    UNIQUE (command_id, plan_id, plan_revision, batch_id, actor_scope_id, actor_user_id,
        installation_id, node_id, action),
    UNIQUE (plan_id, plan_revision, node_id, action),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES control_upgrade_rollout_events(plan_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id, actor_scope_id, actor_user_id, installation_id)
        REFERENCES control_upgrade_rollout_plans(id, actor_scope_id, actor_user_id, installation_id)
        ON DELETE RESTRICT
);

CREATE TABLE control_upgrade_outbox (
    id uuid PRIMARY KEY,
    command_id uuid NOT NULL UNIQUE,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL,
    batch_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    action text NOT NULL,
    topic text NOT NULL,
    message_key text NOT NULL,
    payload_bytes bytea NOT NULL,
    payload_sha256 bytea NOT NULL,
    state text NOT NULL,
    available_at timestamptz NOT NULL,
    claimed_by text,
    claim_token uuid,
    claimed_at timestamptz,
    claim_expires_at timestamptz,
    attempt_count integer NOT NULL,
    published_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL,
    CHECK (id = command_id),
    FOREIGN KEY (command_id, plan_id, plan_revision, batch_id, actor_scope_id, actor_user_id,
        installation_id, node_id, action)
        REFERENCES control_upgrade_node_commands(command_id, plan_id, plan_revision, batch_id,
            actor_scope_id, actor_user_id, installation_id, node_id, action)
        ON DELETE RESTRICT
);

CREATE TABLE control_upgrade_status_receipts (
    command_id uuid NOT NULL,
    status_revision bigint NOT NULL,
    status_id uuid NOT NULL UNIQUE,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL,
    batch_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    action text NOT NULL,
    status_bytes bytea NOT NULL,
    status_sha256 bytea NOT NULL,
    command_sha256 bytea NOT NULL,
    state text NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (command_id, status_revision),
    UNIQUE (command_id, status_id),
    FOREIGN KEY (command_id, plan_id, plan_revision, batch_id, actor_scope_id, actor_user_id,
        installation_id, node_id, action)
        REFERENCES control_upgrade_node_commands(command_id, plan_id, plan_revision, batch_id,
            actor_scope_id, actor_user_id, installation_id, node_id, action)
        ON DELETE RESTRICT
);

CREATE INDEX control_upgrade_outbox_claim_093
    ON control_upgrade_outbox(state, available_at, claim_expires_at, id)
    WHERE state <> 'published';

CREATE FUNCTION validate_control_upgrade_plan_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_snapshot_document jsonb;
    new_snapshot_document jsonb;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'upgrade rollout plans are immutable facts' USING ERRCODE = 'P9302';
    END IF;
    IF NEW.schema_version <> 1 OR NEW.revision < 1 OR NEW.active_batch < -1 OR
       octet_length(NEW.canonical_snapshot_bytes) = 0 OR
       octet_length(NEW.canonical_snapshot_sha256) <> 32 OR
       sha256(NEW.canonical_snapshot_bytes) <> NEW.canonical_snapshot_sha256 OR
       NEW.state NOT IN ('queued','canary','running','paused','rolling_back','completed','failed') OR
       NEW.resume_state NOT IN ('','canary','running') OR
       NEW.completion NOT IN ('','upgraded','rolled_back') THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan tuple' USING ERRCODE = 'P9302';
    END IF;
    BEGIN
        new_snapshot_document := convert_from(NEW.canonical_snapshot_bytes,'UTF8')::jsonb;
        IF TG_OP = 'UPDATE' THEN
            old_snapshot_document := convert_from(OLD.canonical_snapshot_bytes,'UTF8')::jsonb;
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan snapshot json' USING ERRCODE = 'P9302';
    END;
    IF jsonb_typeof(new_snapshot_document) <> 'object' OR
       new_snapshot_document->>'ID' IS DISTINCT FROM NEW.id::text OR
       new_snapshot_document->'SchemaVersion' IS DISTINCT FROM to_jsonb(NEW.schema_version) OR
       new_snapshot_document->'Revision' IS DISTINCT FROM to_jsonb(NEW.revision) OR
       new_snapshot_document->>'State' IS DISTINCT FROM NEW.state OR
       new_snapshot_document->>'ResumeState' IS DISTINCT FROM NEW.resume_state OR
       new_snapshot_document->>'Completion' IS DISTINCT FROM NEW.completion OR
       new_snapshot_document->'ActiveBatch' IS DISTINCT FROM to_jsonb(NEW.active_batch) THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan snapshot binding' USING ERRCODE = 'P9302';
    END IF;
    IF TG_OP = 'UPDATE' AND (
       ROW(NEW.id,NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id,NEW.schema_version,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.actor_scope_id,OLD.actor_user_id,OLD.installation_id,OLD.schema_version,OLD.created_at)
       OR NEW.revision <= OLD.revision OR
       new_snapshot_document - ARRAY['State','ResumeState','Completion','Revision','ActiveBatch',
           'RollbackBatches','NodeStates','NodeDispatchRevisions','CommandReceipts','HealthReceipts']
       IS DISTINCT FROM
       old_snapshot_document - ARRAY['State','ResumeState','Completion','Revision','ActiveBatch',
           'RollbackBatches','NodeStates','NodeDispatchRevisions','CommandReceipts','HealthReceipts']) THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan mutation' USING ERRCODE = 'P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_upgrade_event_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_scope uuid;
    bound_user uuid;
    bound_installation uuid;
    plan_revision bigint;
    maximum_event_revision bigint;
    causation_document jsonb;
    event_document jsonb;
    result_document jsonb;
    result_document_exact json;
    receipt_causation jsonb;
    receipt_event jsonb;
    receipt_causation_bytes bytea;
    receipt_event_bytes bytea;
    receipt_count bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'upgrade rollout events are immutable facts' USING ERRCODE = 'P9302';
    END IF;
    IF NEW.revision < 2 OR octet_length(NEW.causation_bytes) = 0 OR
       octet_length(NEW.causation_sha256) <> 32 OR
       sha256(NEW.causation_bytes) <> NEW.causation_sha256 OR
       octet_length(NEW.event_bytes) = 0 OR octet_length(NEW.event_sha256) <> 32 OR
       sha256(NEW.event_bytes) <> NEW.event_sha256 OR
       octet_length(NEW.result_snapshot_bytes) = 0 OR
       octet_length(NEW.result_snapshot_sha256) <> 32 OR
       sha256(NEW.result_snapshot_bytes) <> NEW.result_snapshot_sha256 THEN
        RAISE EXCEPTION 'invalid upgrade rollout event tuple' USING ERRCODE = 'P9302';
    END IF;
    BEGIN
        causation_document := convert_from(NEW.causation_bytes,'UTF8')::jsonb;
        event_document := convert_from(NEW.event_bytes,'UTF8')::jsonb;
        result_document := convert_from(NEW.result_snapshot_bytes,'UTF8')::jsonb;
        result_document_exact := convert_from(NEW.result_snapshot_bytes,'UTF8')::json;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid upgrade rollout event json' USING ERRCODE = 'P9302';
    END;
    IF jsonb_typeof(causation_document) <> 'object' OR
       causation_document->>'ID' IS DISTINCT FROM NEW.causation_id::text OR
       jsonb_typeof(event_document) <> 'object' OR
       event_document->>'ID' IS DISTINCT FROM NEW.event_id::text OR
       event_document->'Revision' IS DISTINCT FROM to_jsonb(NEW.revision) OR
       jsonb_typeof(result_document) <> 'object' OR
       jsonb_typeof(result_document->'CommandReceipts') NOT IN ('array','null') OR
       jsonb_typeof(result_document->'HealthReceipts') NOT IN ('array','null') THEN
        RAISE EXCEPTION 'invalid upgrade rollout causation document' USING ERRCODE = 'P9302';
    END IF;
    SELECT count(*),(array_agg(receipt_cause))[1],(array_agg(receipt_value))[1]
    INTO receipt_count,receipt_causation,receipt_event
    FROM (
        SELECT receipt->'Command' AS receipt_cause,receipt->'Event' AS receipt_value
        FROM jsonb_array_elements(CASE
            WHEN jsonb_typeof(result_document->'CommandReceipts') = 'array'
            THEN result_document->'CommandReceipts' ELSE '[]'::jsonb END) receipt
        WHERE receipt->'Event'->>'Revision' = NEW.revision::text
        UNION ALL
        SELECT receipt->'Health' AS receipt_cause,receipt->'Event' AS receipt_value
        FROM jsonb_array_elements(CASE
            WHEN jsonb_typeof(result_document->'HealthReceipts') = 'array'
            THEN result_document->'HealthReceipts' ELSE '[]'::jsonb END) receipt
        WHERE receipt->'Event'->>'Revision' = NEW.revision::text
    ) receipts;
    SELECT (array_agg(convert_to((receipt_cause)::text,'UTF8')))[1],
           (array_agg(convert_to((receipt_value)::text,'UTF8')))[1]
    INTO receipt_causation_bytes,receipt_event_bytes
    FROM (
        SELECT receipt->'Command' AS receipt_cause,receipt->'Event' AS receipt_value
        FROM json_array_elements(CASE
            WHEN json_typeof(result_document_exact->'CommandReceipts') = 'array'
            THEN result_document_exact->'CommandReceipts' ELSE '[]'::json END) receipt
        WHERE receipt->'Event'->>'Revision' = NEW.revision::text
        UNION ALL
        SELECT receipt->'Health' AS receipt_cause,receipt->'Event' AS receipt_value
        FROM json_array_elements(CASE
            WHEN json_typeof(result_document_exact->'HealthReceipts') = 'array'
            THEN result_document_exact->'HealthReceipts' ELSE '[]'::json END) receipt
        WHERE receipt->'Event'->>'Revision' = NEW.revision::text
    ) exact_receipts;
    IF receipt_count <> 1 OR receipt_causation IS DISTINCT FROM causation_document OR
       receipt_event IS DISTINCT FROM event_document OR
       receipt_causation_bytes IS DISTINCT FROM NEW.causation_bytes OR
       receipt_event_bytes IS DISTINCT FROM NEW.event_bytes THEN
        RAISE EXCEPTION 'upgrade rollout event does not match result receipt' USING ERRCODE = 'P9302';
    END IF;
    SELECT actor_scope_id,actor_user_id,installation_id,revision
    INTO bound_scope,bound_user,bound_installation,plan_revision
    FROM control_upgrade_rollout_plans WHERE id = NEW.plan_id FOR UPDATE;
    IF NOT FOUND OR ROW(NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id)
       IS DISTINCT FROM ROW(bound_scope,bound_user,bound_installation) THEN
        RAISE EXCEPTION 'invalid upgrade rollout event binding' USING ERRCODE = 'P9302';
    END IF;
    SELECT max(revision) INTO maximum_event_revision
    FROM control_upgrade_rollout_events WHERE plan_id = NEW.plan_id;
    IF NEW.revision <> GREATEST(plan_revision,COALESCE(maximum_event_revision,plan_revision)) + 1 THEN
        RAISE EXCEPTION 'invalid upgrade rollout event revision' USING ERRCODE = 'P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_upgrade_event_history_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_plan uuid;
    plan_revision bigint;
    plan_snapshot bytea;
    plan_snapshot_sha bytea;
    event_count bigint;
    minimum_revision bigint;
    maximum_revision bigint;
    final_snapshot bytea;
    final_snapshot_sha bytea;
BEGIN
    IF TG_TABLE_NAME = 'control_upgrade_rollout_plans' THEN
        target_plan := NEW.id;
    ELSE
        target_plan := NEW.plan_id;
    END IF;
    SELECT revision,canonical_snapshot_bytes,canonical_snapshot_sha256
    INTO plan_revision,plan_snapshot,plan_snapshot_sha
    FROM control_upgrade_rollout_plans WHERE id = target_plan FOR UPDATE;
    SELECT count(*),min(revision),max(revision) INTO event_count,minimum_revision,maximum_revision
    FROM control_upgrade_rollout_events WHERE plan_id = target_plan;
    IF event_count > 0 THEN
        SELECT result_snapshot_bytes,result_snapshot_sha256
        INTO final_snapshot,final_snapshot_sha
        FROM control_upgrade_rollout_events
        WHERE plan_id = target_plan AND revision = maximum_revision;
    END IF;
    IF (plan_revision = 1 AND event_count <> 0) OR
       (plan_revision > 1 AND (event_count <> plan_revision - 1 OR minimum_revision <> 2 OR
        maximum_revision <> plan_revision OR final_snapshot IS DISTINCT FROM plan_snapshot OR
        final_snapshot_sha IS DISTINCT FROM plan_snapshot_sha)) THEN
        RAISE EXCEPTION 'incomplete upgrade rollout event history' USING ERRCODE = 'P9302';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_control_upgrade_command_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_scope uuid;
    bound_user uuid;
    bound_installation uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'upgrade node commands cannot be deleted' USING ERRCODE = 'P9302';
    END IF;
    IF NEW.action NOT IN ('upgrade','rollback') OR NEW.state NOT IN ('pending','published','acknowledged') OR
       octet_length(NEW.signed_execution_bytes) = 0 OR
       octet_length(NEW.signed_execution_sha256) <> 32 OR
       sha256(NEW.signed_execution_bytes) <> NEW.signed_execution_sha256 OR
       (NEW.state = 'pending' AND (NEW.published_at IS NOT NULL OR NEW.acknowledged_at IS NOT NULL)) OR
       (NEW.state = 'published' AND (NEW.published_at IS NULL OR NEW.acknowledged_at IS NOT NULL)) OR
       (NEW.state = 'acknowledged' AND (NEW.published_at IS NULL OR NEW.acknowledged_at IS NULL)) THEN
        RAISE EXCEPTION 'invalid upgrade node command tuple' USING ERRCODE = 'P9302';
    END IF;
    SELECT actor_scope_id,actor_user_id,installation_id
    INTO bound_scope,bound_user,bound_installation
    FROM control_upgrade_rollout_plans WHERE id = NEW.plan_id FOR UPDATE;
    IF NOT FOUND OR ROW(NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id)
       IS DISTINCT FROM ROW(bound_scope,bound_user,bound_installation) THEN
        RAISE EXCEPTION 'invalid upgrade node command binding' USING ERRCODE = 'P9302';
    END IF;
    IF TG_OP = 'UPDATE' AND ROW(
       NEW.command_id,NEW.plan_id,NEW.plan_revision,NEW.batch_id,NEW.actor_scope_id,NEW.actor_user_id,
       NEW.installation_id,NEW.node_id,NEW.action,NEW.signed_execution_bytes,NEW.signed_execution_sha256,
       NEW.created_at) IS DISTINCT FROM ROW(
       OLD.command_id,OLD.plan_id,OLD.plan_revision,OLD.batch_id,OLD.actor_scope_id,OLD.actor_user_id,
       OLD.installation_id,OLD.node_id,OLD.action,OLD.signed_execution_bytes,OLD.signed_execution_sha256,
       OLD.created_at) THEN
        RAISE EXCEPTION 'immutable upgrade node command changed' USING ERRCODE = 'P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_upgrade_outbox_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command control_upgrade_node_commands%ROWTYPE;
    payload_document jsonb;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'upgrade outbox rows cannot be deleted' USING ERRCODE = 'P9302';
    END IF;
    IF NEW.id <> NEW.command_id OR NEW.topic !~ '^[a-z][a-z0-9._-]{0,127}$' OR
       btrim(NEW.message_key) = '' OR octet_length(NEW.payload_bytes) = 0 OR
       octet_length(NEW.payload_sha256) <> 32 OR
       sha256(NEW.payload_bytes) <> NEW.payload_sha256 OR NEW.attempt_count < 0 OR
       NEW.state NOT IN ('pending','claimed','unknown','published') OR
       (NEW.last_error_code IS NOT NULL AND NEW.last_error_code !~ '^[a-z][a-z0-9_]{0,95}$') OR
       (NEW.state = 'pending' AND (NEW.claimed_by IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claimed_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR NEW.published_at IS NOT NULL)) OR
       (NEW.state = 'claimed' AND (NEW.claimed_by IS NULL OR NEW.claim_token IS NULL OR
        NEW.claimed_at IS NULL OR NEW.claim_expires_at IS NULL OR NEW.published_at IS NOT NULL OR
        NEW.claim_expires_at <= NEW.claimed_at)) OR
       (NEW.state = 'unknown' AND (NEW.claimed_by IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claimed_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR NEW.published_at IS NOT NULL OR
        NEW.last_error_code IS NULL)) OR
       (NEW.state = 'published' AND (NEW.claimed_by IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claimed_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR NEW.published_at IS NULL)) THEN
        RAISE EXCEPTION 'invalid upgrade outbox tuple' USING ERRCODE = 'P9302';
    END IF;
    SELECT * INTO command FROM control_upgrade_node_commands WHERE command_id = NEW.command_id;
    IF NOT FOUND OR ROW(NEW.plan_id,NEW.plan_revision,NEW.batch_id,NEW.actor_scope_id,NEW.actor_user_id,
       NEW.installation_id,NEW.node_id,NEW.action) IS DISTINCT FROM ROW(command.plan_id,command.plan_revision,
       command.batch_id,command.actor_scope_id,command.actor_user_id,command.installation_id,command.node_id,
       command.action) THEN
        RAISE EXCEPTION 'invalid upgrade outbox binding' USING ERRCODE = 'P9302';
    END IF;
    BEGIN
        payload_document := convert_from(NEW.payload_bytes,'UTF8')::jsonb;
        IF jsonb_typeof(payload_document) <> 'object' OR
           payload_document->>'schema' IS DISTINCT FROM 'cdnca.edge.upgrade.command/v1' OR
           payload_document->>'command_id' IS DISTINCT FROM NEW.command_id::text OR
           payload_document->>'plan_id' IS DISTINCT FROM NEW.plan_id::text OR
           payload_document->'plan_revision' IS DISTINCT FROM to_jsonb(NEW.plan_revision) OR
           payload_document->>'batch_id' IS DISTINCT FROM NEW.batch_id::text OR
           payload_document->>'installation_id' IS DISTINCT FROM NEW.installation_id::text OR
           payload_document->>'node_id' IS DISTINCT FROM NEW.node_id::text OR
           payload_document->>'action' IS DISTINCT FROM NEW.action OR
           decode(payload_document->>'signed_execution','base64') IS DISTINCT FROM command.signed_execution_bytes OR
           payload_document->>'signed_execution_sha256' IS DISTINCT FROM
             encode(command.signed_execution_sha256,'hex') THEN
            RAISE EXCEPTION 'invalid upgrade outbox command document' USING ERRCODE = 'P9302';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9302' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid upgrade outbox command json' USING ERRCODE = 'P9302';
    END;
    IF TG_OP = 'UPDATE' AND ROW(NEW.id,NEW.command_id,NEW.plan_id,NEW.plan_revision,NEW.batch_id,
       NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id,NEW.node_id,NEW.action,NEW.topic,
       NEW.message_key,NEW.payload_bytes,NEW.payload_sha256,NEW.created_at) IS DISTINCT FROM ROW(
       OLD.id,OLD.command_id,OLD.plan_id,OLD.plan_revision,OLD.batch_id,OLD.actor_scope_id,OLD.actor_user_id,
       OLD.installation_id,OLD.node_id,OLD.action,OLD.topic,OLD.message_key,OLD.payload_bytes,
       OLD.payload_sha256,OLD.created_at) THEN
        RAISE EXCEPTION 'immutable upgrade outbox payload changed' USING ERRCODE = 'P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_upgrade_command_outbox_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_command uuid;
BEGIN
    target_command := CASE WHEN TG_TABLE_NAME = 'control_upgrade_outbox' THEN NEW.command_id ELSE NEW.command_id END;
    IF NOT EXISTS (
        SELECT 1 FROM control_upgrade_node_commands command
        JOIN control_upgrade_outbox outbox ON outbox.command_id = command.command_id
        WHERE command.command_id = target_command AND outbox.id = command.command_id AND
          ROW(outbox.plan_id,outbox.plan_revision,outbox.batch_id,outbox.actor_scope_id,outbox.actor_user_id,
              outbox.installation_id,outbox.node_id,outbox.action) =
          ROW(command.plan_id,command.plan_revision,command.batch_id,command.actor_scope_id,command.actor_user_id,
              command.installation_id,command.node_id,command.action)
    ) THEN
        RAISE EXCEPTION 'upgrade node command requires one bound outbox row' USING ERRCODE = 'P9302';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_control_upgrade_status_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command control_upgrade_node_commands%ROWTYPE;
    previous_revision bigint;
    previous_state text;
    previous_observed_at timestamptz;
    previous_status_bytes bytea;
    previous_status_document jsonb;
    previous_installer_transaction_id text;
    command_payload_sha bytea;
    status_document jsonb;
    status_field_count bigint;
    installer_transaction_id text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'upgrade status receipts are immutable facts' USING ERRCODE = 'P9302';
    END IF;
    IF NEW.status_revision < 1 OR octet_length(NEW.status_bytes) = 0 OR
       octet_length(NEW.status_sha256) <> 32 OR sha256(NEW.status_bytes) <> NEW.status_sha256 OR
       octet_length(NEW.command_sha256) <> 32 THEN
        RAISE EXCEPTION 'invalid upgrade status tuple' USING ERRCODE = 'P9302';
    END IF;
    SELECT * INTO command FROM control_upgrade_node_commands WHERE command_id = NEW.command_id FOR UPDATE;
    IF NOT FOUND OR ROW(NEW.plan_id,NEW.plan_revision,NEW.batch_id,NEW.actor_scope_id,NEW.actor_user_id,
       NEW.installation_id,NEW.node_id,NEW.action) IS DISTINCT FROM ROW(command.plan_id,command.plan_revision,
       command.batch_id,command.actor_scope_id,command.actor_user_id,command.installation_id,command.node_id,
       command.action) OR command.state NOT IN ('published','acknowledged') OR command.published_at IS NULL THEN
        RAISE EXCEPTION 'invalid upgrade status binding' USING ERRCODE = 'P9302';
    END IF;
    SELECT payload_sha256 INTO command_payload_sha
    FROM control_upgrade_outbox WHERE command_id = NEW.command_id FOR UPDATE;
    IF NOT FOUND OR NEW.command_sha256 <> command_payload_sha THEN
        RAISE EXCEPTION 'invalid upgrade status command digest' USING ERRCODE = 'P9302';
    END IF;
    BEGIN
        status_document := convert_from(NEW.status_bytes,'UTF8')::jsonb;
        SELECT count(*) INTO status_field_count FROM jsonb_object_keys(status_document);
        installer_transaction_id := status_document->>'installer_transaction_id';
        IF jsonb_typeof(status_document) <> 'object' OR status_field_count <> 16 OR NOT
           (status_document ?& ARRAY['schema','status_id','status_revision','command_id','plan_id',
            'plan_revision','installation_id','node_id','command_sha256','state','current_version',
            'previous_version','installer_transaction_id','error_code','alert_required','observed_at']) OR
           status_document ? 'batch_id' OR status_document ? 'action' OR
           status_document->>'schema' IS DISTINCT FROM 'cdnca.edge.upgrade.status/v1' OR
           status_document->>'status_id' IS DISTINCT FROM NEW.status_id::text OR
           status_document->'status_revision' IS DISTINCT FROM to_jsonb(NEW.status_revision) OR
           status_document->>'command_id' IS DISTINCT FROM NEW.command_id::text OR
           status_document->>'plan_id' IS DISTINCT FROM NEW.plan_id::text OR
           status_document->'plan_revision' IS DISTINCT FROM to_jsonb(NEW.plan_revision) OR
           status_document->>'installation_id' IS DISTINCT FROM NEW.installation_id::text OR
           status_document->>'node_id' IS DISTINCT FROM NEW.node_id::text OR
           status_document->>'command_sha256' IS DISTINCT FROM encode(command_payload_sha,'hex') OR
           status_document->>'state' IS DISTINCT FROM NEW.state OR
           jsonb_typeof(status_document->'current_version') IS DISTINCT FROM 'string' OR
           jsonb_typeof(status_document->'previous_version') IS DISTINCT FROM 'string' OR
           jsonb_typeof(status_document->'installer_transaction_id') IS DISTINCT FROM 'string' OR
           jsonb_typeof(status_document->'error_code') IS DISTINCT FROM 'string' OR
           jsonb_typeof(status_document->'alert_required') IS DISTINCT FROM 'boolean' OR
           (status_document->>'observed_at')::timestamptz IS DISTINCT FROM NEW.observed_at OR
           (installer_transaction_id <> '' AND installer_transaction_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
           (status_document->>'error_code' <> '' AND
            status_document->>'error_code' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') THEN
            RAISE EXCEPTION 'invalid upgrade status document' USING ERRCODE = 'P9302';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9302' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid upgrade status json' USING ERRCODE = 'P9302';
    END;
    IF NEW.state NOT IN ('accepted','claimed','installing','healthy','failed','rolling_back','rolled_back','uncertain') THEN
        RAISE EXCEPTION 'invalid upgrade status state' USING ERRCODE = 'P9302';
    END IF;
    SELECT status_revision,state,observed_at,status_bytes
    INTO previous_revision,previous_state,previous_observed_at,previous_status_bytes
    FROM control_upgrade_status_receipts WHERE command_id = NEW.command_id
    ORDER BY status_revision DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.status_revision <> 1 OR NEW.state NOT IN ('accepted','claimed') THEN
            RAISE EXCEPTION 'invalid initial upgrade status' USING ERRCODE = 'P9302';
        END IF;
    ELSIF NEW.status_revision <> previous_revision + 1 OR NEW.observed_at < previous_observed_at OR NOT (
       (previous_state = 'accepted' AND NEW.state = 'claimed') OR
       (previous_state = 'claimed' AND NEW.state = 'installing') OR
       (previous_state = 'installing' AND NEW.state IN ('healthy','failed','rolling_back','uncertain')) OR
       (previous_state = 'rolling_back' AND NEW.state IN ('rolled_back','failed','uncertain')) OR
       (previous_state = 'uncertain' AND NEW.state IN ('uncertain','healthy','failed','rolled_back'))
    ) THEN
        RAISE EXCEPTION 'invalid upgrade status transition' USING ERRCODE = 'P9302';
    END IF;
    IF previous_state = 'uncertain' THEN
        BEGIN
            previous_status_document := convert_from(previous_status_bytes,'UTF8')::jsonb;
            previous_installer_transaction_id := previous_status_document->>'installer_transaction_id';
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid previous upgrade status json' USING ERRCODE = 'P9302';
        END;
        IF previous_installer_transaction_id = '' OR
           installer_transaction_id IS DISTINCT FROM previous_installer_transaction_id THEN
            RAISE EXCEPTION 'invalid upgrade status reconciliation' USING ERRCODE = 'P9302';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_plan_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_rollout_plans
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_plan_093();

CREATE TRIGGER control_upgrade_event_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_rollout_events
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_event_093();

CREATE CONSTRAINT TRIGGER control_upgrade_plan_history_093
AFTER INSERT OR UPDATE ON control_upgrade_rollout_plans
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_control_upgrade_event_history_093();

CREATE CONSTRAINT TRIGGER control_upgrade_event_history_093
AFTER INSERT ON control_upgrade_rollout_events
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_control_upgrade_event_history_093();

CREATE TRIGGER control_upgrade_command_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_node_commands
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_command_093();

CREATE TRIGGER control_upgrade_outbox_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_outbox
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_outbox_093();

CREATE CONSTRAINT TRIGGER control_upgrade_command_outbox_093
AFTER INSERT OR UPDATE ON control_upgrade_node_commands
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_control_upgrade_command_outbox_093();

CREATE CONSTRAINT TRIGGER control_upgrade_outbox_command_093
AFTER INSERT OR UPDATE ON control_upgrade_outbox
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_control_upgrade_command_outbox_093();

CREATE TRIGGER control_upgrade_status_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_093();

REVOKE ALL ON FUNCTION validate_control_upgrade_plan_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_event_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_event_history_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_command_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_outbox_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_command_outbox_093() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_status_093() FROM PUBLIC;
