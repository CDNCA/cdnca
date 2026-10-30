LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 96 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 96 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=96 AND migration_id='096_upgrade_runtime_control'
          AND checksum_sha256='5f6cbeaec3ea9d0e0b59861516575147a6b897022c5f25d911c115976d72214f'
          AND down_checksum_sha256='3f1302b42bbe9a841da0892a989422d661407a381a1052522634ed0335f3eac4'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 097 requires the exact verified 096 release head'
            USING ERRCODE = 'P9700';
    END IF;
END;
$$;

LOCK TABLE control_upgrade_rollout_plans,
    control_upgrade_rollout_events,
    control_upgrade_status_receipts,
    control_upgrade_grant_intents_096
IN ACCESS EXCLUSIVE MODE;

ALTER TABLE control_upgrade_rollout_plans
    ADD CONSTRAINT control_upgrade_rollout_license_identity_097_uk
    UNIQUE (id,installation_id,parent_grant_id);

CREATE FUNCTION control_upgrade_license_receipt_digest_097(
    request_id uuid,
    installation_id uuid,
    grant_id uuid,
    status text,
    installed_version text,
    error_code text,
    observed_at timestamptz
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    encoded bytea := ''::bytea;
    value text;
BEGIN
    FOREACH value IN ARRAY ARRAY[
        'cdnca-upgrade-grant-receipt-idempotency/v2',
        'upgrade-grant.receipt-request/v2',
        request_id::text,
        installation_id::text,
        grant_id::text,
        status,
        installed_version,
        error_code,
        extract(epoch FROM observed_at)::bigint::text
    ] LOOP
        encoded := encoded || int4send(octet_length(convert_to(value,'UTF8'))) || convert_to(value,'UTF8');
    END LOOP;
    RETURN sha256(encoded);
END;
$$;

CREATE FUNCTION control_upgrade_license_receipt_id_097(plan_id uuid, receipt_kind text)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    digest bytea;
BEGIN
    digest := sha256(convert_to(
        'cdnca-control-upgrade-license-receipt-id/v1:' || plan_id::text || ':' || receipt_kind,
        'UTF8'));
    digest := set_byte(digest,6,(get_byte(digest,6) & 15) | 80);
    digest := set_byte(digest,8,(get_byte(digest,8) & 63) | 128);
    RETURN encode(substring(digest FROM 1 FOR 16),'hex')::uuid;
END;
$$;

CREATE FUNCTION control_upgrade_license_receipt_reason_097(snapshot_bytes bytea)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    snapshot_document jsonb;
    item record;
    code text;
BEGIN
    BEGIN
        snapshot_document := convert_from(snapshot_bytes,'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
    FOR item IN
        SELECT value,ordinality
        FROM jsonb_array_elements(COALESCE(snapshot_document->'HealthReceipts','[]'::jsonb))
             WITH ORDINALITY
        ORDER BY ordinality DESC
    LOOP
        code := upper(COALESCE(item.value->'Health'->>'Code',''));
        CASE code
        WHEN 'DOWNLOAD_FAILED' THEN RETURN 'download_failed';
        WHEN 'HEALTH_FAILED' THEN RETURN 'health_check_failed';
        WHEN 'UPGRADE_FAILED','INSTALLER_ROLLED_BACK' THEN RETURN 'atomic_apply_failed';
        WHEN 'ARTIFACT_INTEGRITY_FAILED','ARTIFACT_TOO_LARGE','INSUFFICIENT_DISK','PLAN_EXPIRED' THEN
            RETURN 'preflight_failed';
        WHEN '' THEN NULL;
        WHEN 'ROLLBACK_FAILED','UNKNOWN_OUTCOME','INSTALLER_OUTCOME_UNKNOWN',
             'INSTALLER_UNCERTAIN','CONFLICTING_TERMINAL_STATE' THEN
            RETURN NULL;
        ELSE
            RETURN NULL;
        END CASE;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE TABLE control_upgrade_license_receipt_outbox_097 (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    request_schema text NOT NULL,
    request_digest_schema smallint NOT NULL,
    logical_digest bytea NOT NULL,
    receipt_sequence smallint NOT NULL,
    status text NOT NULL,
    installed_version text NOT NULL,
    error_code text,
    observed_at timestamptz NOT NULL,
    predecessor_id uuid,
    state text NOT NULL CHECK (state IN ('pending','claimed','delivered','failed')),
    available_at timestamptz NOT NULL,
    claimed_by text,
    claim_token uuid,
    claimed_at timestamptz,
    claim_expires_at timestamptz,
    attempt_count bigint NOT NULL,
    last_error_code text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (plan_id,status),
    UNIQUE (plan_id,receipt_sequence),
    UNIQUE (installation_id,request_id),
    UNIQUE (installation_id,grant_id,status),
    UNIQUE (id,logical_digest,status),
    FOREIGN KEY (plan_id,installation_id,grant_id)
        REFERENCES control_upgrade_rollout_plans(id,installation_id,parent_grant_id) ON DELETE RESTRICT,
    FOREIGN KEY (predecessor_id)
        REFERENCES control_upgrade_license_receipt_outbox_097(id) ON DELETE RESTRICT,
    CHECK (request_schema='upgrade-grant.receipt-request/v2'),
    CHECK (request_digest_schema=2),
    CHECK (octet_length(logical_digest)=32),
    CHECK (installed_version=btrim(installed_version) AND char_length(installed_version) BETWEEN 5 AND 128),
    CHECK (date_trunc('second',observed_at)=observed_at),
    CHECK (attempt_count>=0),
    CHECK (updated_at>=created_at),
    CHECK (claim_expires_at IS NULL OR claim_expires_at>claimed_at),
    CHECK (
        (state='pending' AND claimed_by IS NULL AND claim_token IS NULL AND claimed_at IS NULL AND claim_expires_at IS NULL) OR
        (state='claimed' AND claimed_by IS NOT NULL AND claim_token IS NOT NULL AND claimed_at IS NOT NULL AND claim_expires_at IS NOT NULL) OR
        (state IN ('delivered','failed') AND claimed_by IS NULL AND claim_token IS NULL AND claimed_at IS NULL AND claim_expires_at IS NULL)
    )
);

CREATE TABLE control_upgrade_license_receipt_deliveries_097 (
    request_id uuid PRIMARY KEY,
    logical_digest bytea NOT NULL,
    response_schema text NOT NULL,
    receipt_id uuid NOT NULL UNIQUE,
    accepted_status text NOT NULL,
    received_at timestamptz NOT NULL,
    response_bytes bytea NOT NULL,
    response_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (request_id,logical_digest,accepted_status),
    FOREIGN KEY (request_id,logical_digest,accepted_status)
        REFERENCES control_upgrade_license_receipt_outbox_097(id,logical_digest,status) ON DELETE RESTRICT,
    CHECK (response_schema='upgrade-grant.receipt-response/v1'),
    CHECK (octet_length(logical_digest)=32),
    CHECK (octet_length(response_bytes)>0 AND octet_length(response_sha256)=32 AND sha256(response_bytes)=response_sha256),
    CHECK (date_trunc('second',received_at)=received_at)
);

CREATE FUNCTION validate_control_upgrade_license_receipt_fact_097(
    receipt control_upgrade_license_receipt_outbox_097
)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    plan_record control_upgrade_rollout_plans%ROWTYPE;
    intent_record control_upgrade_grant_intents_096%ROWTYPE;
    plan_document jsonb;
    event_record record;
    event_document jsonb;
    expected_error text;
    has_applied boolean;
BEGIN
    SELECT * INTO plan_record FROM control_upgrade_rollout_plans
    WHERE id=receipt.plan_id FOR SHARE;
    IF NOT FOUND OR plan_record.schema_version<>2 OR
       plan_record.installation_id<>receipt.installation_id OR
       plan_record.parent_grant_id<>receipt.grant_id THEN
        RETURN false;
    END IF;
    BEGIN
        plan_document := convert_from(plan_record.canonical_snapshot_bytes,'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    IF receipt.receipt_sequence IN (1,2) THEN
        SELECT * INTO intent_record FROM control_upgrade_grant_intents_096
        WHERE plan_id=receipt.plan_id AND candidate_plan_id=receipt.plan_id AND state='consumed'
        FOR SHARE;
        RETURN FOUND AND intent_record.installation_id=receipt.installation_id AND
            receipt.installed_version=plan_document->>'CurrentVersion' AND
            receipt.observed_at=date_trunc('second',intent_record.updated_at) AND
            ((receipt.receipt_sequence=1 AND receipt.status='fetched') OR
             (receipt.receipt_sequence=2 AND receipt.status='verified'));
    END IF;

    SELECT event.revision,event.created_at,event.result_snapshot_bytes,
           convert_from(event.result_snapshot_bytes,'UTF8')::jsonb AS document
      INTO event_record
    FROM control_upgrade_rollout_events event
    WHERE event.plan_id=receipt.plan_id
      AND date_trunc('second',event.created_at)=receipt.observed_at
      AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'State'='completed'
      AND (
        (receipt.status='applied' AND
         convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'Completion'='upgraded') OR
        (receipt.status IN ('rejected','rolled_back') AND
         convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'Completion'='rolled_back')
      )
    ORDER BY event.revision DESC LIMIT 1 FOR SHARE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    event_document := event_record.document;
    SELECT EXISTS (
        SELECT 1 FROM control_upgrade_rollout_events event
        WHERE event.plan_id=receipt.plan_id AND event.revision<event_record.revision
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'State'='completed'
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'Completion'='upgraded'
    ) INTO has_applied;
    IF receipt.status='applied' THEN
        RETURN receipt.receipt_sequence=3 AND receipt.error_code IS NULL AND
            receipt.installed_version=event_document->>'TargetVersion';
    ELSIF receipt.status='rejected' THEN
        expected_error := control_upgrade_license_receipt_reason_097(event_record.result_snapshot_bytes);
        RETURN receipt.receipt_sequence=3 AND NOT has_applied AND expected_error IS NOT NULL AND
            receipt.error_code=expected_error AND receipt.installed_version=event_document->>'CurrentVersion';
    ELSIF receipt.status='rolled_back' THEN
        RETURN receipt.receipt_sequence=4 AND has_applied AND receipt.error_code IS NULL AND
            receipt.installed_version=event_document->>'CurrentVersion';
    END IF;
    RETURN false;
END;
$$;

CREATE FUNCTION validate_control_upgrade_license_receipt_outbox_097()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous control_upgrade_license_receipt_outbox_097%ROWTYPE;
    expected_digest bytea;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'control upgrade License receipt delivery is immutable' USING ERRCODE = 'P9702';
    END IF;
    IF NEW.id IS NULL OR NEW.id='00000000-0000-0000-0000-000000000000'::uuid OR
       NEW.request_id IS DISTINCT FROM NEW.id OR
       NEW.plan_id IS NULL OR NEW.plan_id='00000000-0000-0000-0000-000000000000'::uuid OR
       NEW.installation_id IS NULL OR NEW.installation_id='00000000-0000-0000-0000-000000000000'::uuid OR
       NEW.grant_id IS NULL OR NEW.grant_id='00000000-0000-0000-0000-000000000000'::uuid OR
       NEW.request_schema IS DISTINCT FROM 'upgrade-grant.receipt-request/v2' OR
       NEW.request_digest_schema IS DISTINCT FROM 2 OR NEW.logical_digest IS NULL OR
       octet_length(NEW.logical_digest)<>32 OR NEW.receipt_sequence IS NULL OR
       NEW.status IS NULL OR NEW.installed_version IS NULL OR
       NEW.installed_version<>btrim(NEW.installed_version) OR
       char_length(NEW.installed_version) NOT BETWEEN 5 AND 128 OR
       NEW.observed_at IS NULL OR date_trunc('second',NEW.observed_at) IS DISTINCT FROM NEW.observed_at OR
       NEW.observed_at<=to_timestamp(0) OR NEW.state IS NULL OR NEW.available_at IS NULL OR
       NEW.attempt_count IS NULL OR NEW.attempt_count<0 OR NEW.created_at IS NULL OR NEW.updated_at IS NULL OR
       NEW.available_at<NEW.observed_at OR NEW.created_at<>NEW.observed_at OR NEW.updated_at<NEW.created_at OR NOT (
        (NEW.receipt_sequence=1 AND NEW.status='fetched' AND NEW.predecessor_id IS NULL AND NEW.error_code IS NULL) OR
        (NEW.receipt_sequence=2 AND NEW.status='verified' AND NEW.predecessor_id IS NOT NULL AND NEW.error_code IS NULL) OR
        (NEW.receipt_sequence=3 AND NEW.status IN ('applied','rejected') AND NEW.predecessor_id IS NOT NULL AND
            ((NEW.status='applied' AND NEW.error_code IS NULL) OR
             (NEW.status='rejected' AND NEW.error_code IN ('download_failed','health_check_failed','atomic_apply_failed','preflight_failed')))) OR
        (NEW.receipt_sequence=4 AND NEW.status='rolled_back' AND NEW.predecessor_id IS NOT NULL AND NEW.error_code IS NULL)
       ) OR NOT (
        (NEW.state='pending' AND NEW.claimed_by IS NULL AND NEW.claim_token IS NULL AND
            NEW.claimed_at IS NULL AND NEW.claim_expires_at IS NULL) OR
        (NEW.state='claimed' AND NEW.claimed_by~'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND
            NEW.claim_token IS NOT NULL AND NEW.claim_token<>'00000000-0000-0000-0000-000000000000'::uuid AND
            NEW.claimed_at IS NOT NULL AND NEW.claim_expires_at IS NOT NULL AND
            NEW.claim_expires_at>NEW.claimed_at) OR
        (NEW.state IN ('delivered','failed') AND NEW.claimed_by IS NULL AND NEW.claim_token IS NULL AND
            NEW.claimed_at IS NULL AND NEW.claim_expires_at IS NULL)
       ) THEN
        RAISE EXCEPTION 'invalid control upgrade License receipt tuple' USING ERRCODE = 'P9702';
    END IF;
    expected_digest := control_upgrade_license_receipt_digest_097(NEW.request_id,NEW.installation_id,
        NEW.grant_id,NEW.status,NEW.installed_version,COALESCE(NEW.error_code,''),NEW.observed_at);
    IF NEW.logical_digest IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'invalid control upgrade License receipt digest' USING ERRCODE = 'P9702';
    END IF;
    IF NEW.predecessor_id IS NOT NULL THEN
        SELECT * INTO previous FROM control_upgrade_license_receipt_outbox_097
        WHERE id=NEW.predecessor_id FOR SHARE;
        IF NOT FOUND OR previous.plan_id<>NEW.plan_id OR previous.installation_id<>NEW.installation_id OR
           previous.grant_id<>NEW.grant_id OR previous.receipt_sequence<>NEW.receipt_sequence-1 OR
           (NEW.receipt_sequence=2 AND previous.status<>'fetched') OR
           (NEW.receipt_sequence=3 AND previous.status<>'verified') OR
           (NEW.receipt_sequence=4 AND previous.status<>'applied') THEN
            RAISE EXCEPTION 'invalid control upgrade License receipt predecessor' USING ERRCODE = 'P9702';
        END IF;
        IF TG_OP='UPDATE' AND OLD.state='pending' AND NEW.state='claimed' AND previous.state<>'delivered' THEN
            RAISE EXCEPTION 'control upgrade License receipt predecessor is not delivered' USING ERRCODE = 'P9702';
        END IF;
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'pending' OR NEW.attempt_count IS DISTINCT FROM 0 OR NEW.claimed_by IS NOT NULL OR
           NEW.claim_token IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR
           NEW.last_error_code IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial control upgrade License receipt state' USING ERRCODE = 'P9702';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.request_id,NEW.plan_id,NEW.installation_id,NEW.grant_id,NEW.request_schema,
       NEW.request_digest_schema,NEW.logical_digest,NEW.receipt_sequence,NEW.status,NEW.installed_version,
       NEW.error_code,NEW.observed_at,NEW.predecessor_id,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.request_id,OLD.plan_id,OLD.installation_id,OLD.grant_id,OLD.request_schema,
       OLD.request_digest_schema,OLD.logical_digest,OLD.receipt_sequence,OLD.status,OLD.installed_version,
       OLD.error_code,OLD.observed_at,OLD.predecessor_id,OLD.created_at) OR NEW.updated_at<OLD.updated_at OR NOT (
        (OLD.state='pending' AND NEW.state='claimed' AND NEW.attempt_count=OLD.attempt_count+1 AND
            NEW.claimed_by~'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND
            NEW.claim_token IS NOT NULL AND NEW.claim_token<>'00000000-0000-0000-0000-000000000000'::uuid AND
            NEW.claimed_at>=OLD.updated_at AND
            NEW.updated_at=NEW.claimed_at AND NEW.claim_expires_at>NEW.claimed_at AND NEW.available_at=OLD.available_at AND
            NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code) OR
        (OLD.state='claimed' AND NEW.state IN ('pending','delivered','failed') AND
            NEW.attempt_count=OLD.attempt_count AND NEW.claimed_by IS NULL AND NEW.claim_token IS NULL AND
            NEW.claimed_at IS NULL AND NEW.claim_expires_at IS NULL AND
            ((NEW.state='pending' AND NEW.available_at>=NEW.updated_at AND NEW.last_error_code IS NOT NULL) OR
             (NEW.state='delivered' AND NEW.available_at=OLD.available_at AND NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code) OR
             (NEW.state='failed' AND NEW.available_at=OLD.available_at AND NEW.last_error_code IS NOT NULL)))
    ) THEN
        RAISE EXCEPTION 'invalid control upgrade License receipt state transition' USING ERRCODE = 'P9702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_license_receipt_outbox_validate_097
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_license_receipt_outbox_097
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_license_receipt_outbox_097();

CREATE FUNCTION validate_control_upgrade_license_receipt_delivery_097()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    outbox control_upgrade_license_receipt_outbox_097%ROWTYPE;
    expected_response bytea;
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'control upgrade License receipt delivery is immutable' USING ERRCODE = 'P9702';
    END IF;
    IF NEW.request_id IS NULL OR NEW.logical_digest IS NULL OR octet_length(NEW.logical_digest)<>32 OR
       NEW.response_schema IS DISTINCT FROM 'upgrade-grant.receipt-response/v1' OR
       NEW.receipt_id IS NULL OR NEW.receipt_id='00000000-0000-0000-0000-000000000000'::uuid OR
       NEW.accepted_status IS NULL OR NEW.received_at IS NULL OR NEW.received_at<=to_timestamp(0) OR
       date_trunc('second',NEW.received_at) IS DISTINCT FROM NEW.received_at OR
       NEW.response_bytes IS NULL OR octet_length(NEW.response_bytes)=0 OR
       NEW.response_sha256 IS NULL OR octet_length(NEW.response_sha256)<>32 OR
       NEW.created_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'invalid control upgrade License receipt delivery tuple' USING ERRCODE = 'P9702';
    END IF;
    SELECT * INTO outbox FROM control_upgrade_license_receipt_outbox_097
    WHERE id=NEW.request_id FOR SHARE;
    expected_response := convert_to(format(
        '{"schema":"upgrade-grant.receipt-response/v1","request_id":"%s","receipt_id":"%s","accepted_status":"%s","received_at":%s}' || E'\n',
        NEW.request_id,NEW.receipt_id,NEW.accepted_status,extract(epoch FROM NEW.received_at)::bigint),'UTF8');
    IF NOT FOUND OR outbox.state<>'claimed' OR NEW.logical_digest IS DISTINCT FROM outbox.logical_digest OR
       NEW.accepted_status IS DISTINCT FROM outbox.status OR NEW.response_bytes IS DISTINCT FROM expected_response OR
       NEW.response_sha256 IS DISTINCT FROM sha256(NEW.response_bytes) THEN
        RAISE EXCEPTION 'invalid control upgrade License receipt delivery' USING ERRCODE = 'P9702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_license_receipt_delivery_validate_097
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_license_receipt_deliveries_097
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_license_receipt_delivery_097();

CREATE FUNCTION enforce_control_upgrade_license_receipt_delivery_097()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME='control_upgrade_license_receipt_outbox_097' THEN
        IF validate_control_upgrade_license_receipt_fact_097(NEW) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'invalid deferred control upgrade License receipt source fact' USING ERRCODE = 'P9702';
        END IF;
        IF (NEW.state='delivered') IS DISTINCT FROM EXISTS (
            SELECT 1 FROM control_upgrade_license_receipt_deliveries_097 delivery
            WHERE delivery.request_id=NEW.id AND delivery.logical_digest=NEW.logical_digest AND
                  delivery.accepted_status=NEW.status
        ) THEN
            RAISE EXCEPTION 'invalid deferred control upgrade License receipt delivery state' USING ERRCODE = 'P9702';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM control_upgrade_license_receipt_outbox_097 outbox
        WHERE outbox.id=NEW.request_id AND outbox.logical_digest=NEW.logical_digest AND
              outbox.status=NEW.accepted_status AND outbox.state='delivered'
    ) THEN
        RAISE EXCEPTION 'invalid deferred control upgrade License receipt delivery fact' USING ERRCODE = 'P9702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER control_upgrade_license_receipt_delivered_097
AFTER INSERT OR UPDATE ON control_upgrade_license_receipt_outbox_097
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_control_upgrade_license_receipt_delivery_097();

CREATE CONSTRAINT TRIGGER control_upgrade_license_receipt_delivery_fact_097
AFTER INSERT ON control_upgrade_license_receipt_deliveries_097
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_control_upgrade_license_receipt_delivery_097();

CREATE FUNCTION prevent_control_upgrade_license_receipt_truncate_097()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control upgrade License receipt delivery is immutable' USING ERRCODE = 'P9702';
END;
$$;

CREATE TRIGGER control_upgrade_license_receipt_outbox_no_truncate_097
BEFORE TRUNCATE ON control_upgrade_license_receipt_outbox_097
FOR EACH STATEMENT EXECUTE FUNCTION prevent_control_upgrade_license_receipt_truncate_097();

CREATE TRIGGER control_upgrade_license_receipt_delivery_no_truncate_097
BEFORE TRUNCATE ON control_upgrade_license_receipt_deliveries_097
FOR EACH STATEMENT EXECUTE FUNCTION prevent_control_upgrade_license_receipt_truncate_097();

CREATE INDEX control_upgrade_license_receipt_claim_097_idx
    ON control_upgrade_license_receipt_outbox_097(state,available_at,plan_id,receipt_sequence,id);

DO $$
DECLARE
    fact record;
    fetched_id uuid;
    verified_id uuid;
    terminal_id uuid;
    applied_event record;
    rollback_event record;
    applied_found boolean;
    observed_at timestamptz;
    terminal_error text;
    terminal_status text;
    terminal_version text;
    terminal_sequence smallint;
    terminal_predecessor uuid;
    receipt_digest bytea;
BEGIN
    FOR fact IN
        SELECT plan.id AS plan_id,plan.installation_id,plan.parent_grant_id,
               plan.canonical_snapshot_bytes,
               convert_from(plan.canonical_snapshot_bytes,'UTF8')::jsonb->>'CurrentVersion' AS current_version,
               intent.updated_at
        FROM control_upgrade_rollout_plans plan
        JOIN control_upgrade_grant_intents_096 intent ON intent.plan_id=plan.id AND
            intent.candidate_plan_id=plan.id AND intent.state='consumed'
        WHERE plan.schema_version=2
        ORDER BY plan.id
    LOOP
        fetched_id := control_upgrade_license_receipt_id_097(fact.plan_id,'fetched');
        verified_id := control_upgrade_license_receipt_id_097(fact.plan_id,'verified');
        observed_at := date_trunc('second',fact.updated_at);
        receipt_digest := control_upgrade_license_receipt_digest_097(fetched_id,fact.installation_id,
            fact.parent_grant_id,'fetched',fact.current_version,'',observed_at);
        INSERT INTO control_upgrade_license_receipt_outbox_097(
            id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
            logical_digest,receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
            state,available_at,attempt_count,created_at,updated_at)
        VALUES(fetched_id,fetched_id,fact.plan_id,fact.installation_id,fact.parent_grant_id,
            'upgrade-grant.receipt-request/v2',2,receipt_digest,1,'fetched',fact.current_version,NULL,
            observed_at,NULL,'pending',observed_at,0,observed_at,observed_at);
        receipt_digest := control_upgrade_license_receipt_digest_097(verified_id,fact.installation_id,
            fact.parent_grant_id,'verified',fact.current_version,'',observed_at);
        INSERT INTO control_upgrade_license_receipt_outbox_097(
            id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
            logical_digest,receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
            state,available_at,attempt_count,created_at,updated_at)
        VALUES(verified_id,verified_id,fact.plan_id,fact.installation_id,fact.parent_grant_id,
            'upgrade-grant.receipt-request/v2',2,receipt_digest,2,'verified',fact.current_version,NULL,
            observed_at,fetched_id,'pending',observed_at,0,observed_at,observed_at);

        SELECT event.created_at,event.result_snapshot_bytes,
               convert_from(event.result_snapshot_bytes,'UTF8')::jsonb AS document
          INTO applied_event
        FROM control_upgrade_rollout_events event
        WHERE event.plan_id=fact.plan_id
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'State'='completed'
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'Completion'='upgraded'
        ORDER BY event.revision DESC LIMIT 1;
        applied_found := FOUND;
        IF applied_found THEN
            terminal_id := control_upgrade_license_receipt_id_097(fact.plan_id,'applied');
            observed_at := date_trunc('second',applied_event.created_at);
            terminal_version := applied_event.document->>'TargetVersion';
            receipt_digest := control_upgrade_license_receipt_digest_097(terminal_id,fact.installation_id,
                fact.parent_grant_id,'applied',terminal_version,'',observed_at);
            INSERT INTO control_upgrade_license_receipt_outbox_097(
                id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
                logical_digest,receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
                state,available_at,attempt_count,created_at,updated_at)
            VALUES(terminal_id,terminal_id,fact.plan_id,fact.installation_id,fact.parent_grant_id,
                'upgrade-grant.receipt-request/v2',2,receipt_digest,3,'applied',terminal_version,NULL,
                observed_at,verified_id,'pending',observed_at,0,observed_at,observed_at);
        END IF;

        SELECT event.created_at,event.result_snapshot_bytes,
               convert_from(event.result_snapshot_bytes,'UTF8')::jsonb AS document
          INTO rollback_event
        FROM control_upgrade_rollout_events event
        WHERE event.plan_id=fact.plan_id
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'State'='completed'
          AND convert_from(event.result_snapshot_bytes,'UTF8')::jsonb->>'Completion'='rolled_back'
        ORDER BY event.revision DESC LIMIT 1;
        IF FOUND THEN
            observed_at := date_trunc('second',rollback_event.created_at);
            terminal_version := rollback_event.document->>'CurrentVersion';
            terminal_error := NULL;
            IF applied_found THEN
                terminal_status := 'rolled_back';
                terminal_sequence := 4;
                terminal_predecessor := control_upgrade_license_receipt_id_097(fact.plan_id,'applied');
            ELSE
                terminal_status := 'rejected';
                terminal_sequence := 3;
                terminal_predecessor := verified_id;
                terminal_error := control_upgrade_license_receipt_reason_097(rollback_event.result_snapshot_bytes);
            END IF;
            IF applied_found OR terminal_error IS NOT NULL THEN
                terminal_id := control_upgrade_license_receipt_id_097(fact.plan_id,terminal_status);
                receipt_digest := control_upgrade_license_receipt_digest_097(terminal_id,fact.installation_id,
                    fact.parent_grant_id,terminal_status,terminal_version,COALESCE(terminal_error,''),observed_at);
                INSERT INTO control_upgrade_license_receipt_outbox_097(
                    id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
                    logical_digest,receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
                    state,available_at,attempt_count,created_at,updated_at)
                VALUES(terminal_id,terminal_id,fact.plan_id,fact.installation_id,fact.parent_grant_id,
                    'upgrade-grant.receipt-request/v2',2,receipt_digest,terminal_sequence,terminal_status,
                    terminal_version,terminal_error,observed_at,terminal_predecessor,'pending',observed_at,0,
                    observed_at,observed_at);
            END IF;
        END IF;
    END LOOP;
END;
$$;

REVOKE ALL ON TABLE control_upgrade_license_receipt_outbox_097 FROM PUBLIC;
REVOKE ALL ON TABLE control_upgrade_license_receipt_deliveries_097 FROM PUBLIC;
REVOKE ALL ON FUNCTION control_upgrade_license_receipt_digest_097(uuid,uuid,uuid,text,text,text,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION control_upgrade_license_receipt_id_097(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control_upgrade_license_receipt_reason_097(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_license_receipt_fact_097(control_upgrade_license_receipt_outbox_097) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_license_receipt_outbox_097() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_license_receipt_delivery_097() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_control_upgrade_license_receipt_delivery_097() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_control_upgrade_license_receipt_truncate_097() FROM PUBLIC;
