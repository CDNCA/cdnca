-- 672 回退：恢复 096/097 原触发器函数（计划只认 schema 1/2、命令授权与投递确认只认计划 schema 1/2、
-- 授权端回执只认计划 schema 2）。已有 schema 3 计划行时拒绝回退（P6722），否则旧函数会让这些计划的
-- 后续命令、投递确认与回执全部写不进库。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE control_upgrade_rollout_plans,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_license_receipt_outbox_097
IN SHARE ROW EXCLUSIVE MODE;

DO $migration_672_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 672 OR
       (SELECT max(version) FROM schema_migrations) <> 672 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=672 AND
        migration_id='672_upgrade_plan_schema_v3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 672 down requires the exact verified migration head' USING ERRCODE='P6721';
    END IF;
    IF EXISTS (SELECT 1 FROM control_upgrade_rollout_plans WHERE schema_version=3) THEN
        RAISE EXCEPTION 'migration 672 rollback would strand schema 3 upgrade rollout plans' USING ERRCODE='P6722';
    END IF;
END;
$migration_672_down$;

CREATE OR REPLACE FUNCTION validate_control_upgrade_plan_093()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_snapshot_document jsonb;
    new_snapshot_document jsonb;
    bundle_document jsonb;
    forward_profile_document jsonb;
    rollback_profile_document jsonb;
    rollback_available boolean;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'upgrade rollout plans are immutable facts' USING ERRCODE='P9302';
    END IF;
    IF NEW.schema_version NOT IN (1,2) OR NEW.revision<1 OR NEW.active_batch< -1 OR
       octet_length(NEW.canonical_snapshot_bytes)=0 OR
       octet_length(NEW.canonical_snapshot_sha256)<>32 OR
       sha256(NEW.canonical_snapshot_bytes)<>NEW.canonical_snapshot_sha256 OR
       NEW.state NOT IN ('queued','canary','running','paused','rolling_back','completed','failed') OR
       NEW.resume_state NOT IN ('','canary','running') OR
       NEW.completion NOT IN ('','upgraded','rolled_back') OR
       (NEW.schema_version=1 AND ROW(NEW.parent_grant_id,NEW.parent_grant_bytes,
            NEW.parent_grant_sha256,NEW.parent_grant_expires_at,NEW.artifact_bundle_id,
            NEW.artifact_bundle_bytes,NEW.artifact_bundle_sha256,NEW.command_issuance_not_after,NEW.forward_profile_bytes,
            NEW.forward_profile_sha256,NEW.rollback_profile_bytes,NEW.rollback_profile_sha256,
            NEW.artifact_size_bytes,NEW.rollback_artifact_size_bytes) IS DISTINCT FROM
            ROW(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)) OR
       (NEW.schema_version=2 AND (
            NEW.parent_grant_id IS NULL OR octet_length(NEW.parent_grant_bytes)=0 OR
            octet_length(NEW.parent_grant_sha256)<>32 OR
            sha256(NEW.parent_grant_bytes)<>NEW.parent_grant_sha256 OR
            NEW.parent_grant_expires_at<=NEW.created_at OR
            NEW.artifact_bundle_id IS NULL OR octet_length(NEW.artifact_bundle_bytes)=0 OR
            octet_length(NEW.artifact_bundle_sha256)<>32 OR
            sha256(NEW.artifact_bundle_bytes)<>NEW.artifact_bundle_sha256 OR
            NEW.command_issuance_not_after<=NEW.created_at OR
            octet_length(NEW.forward_profile_bytes)=0 OR
            octet_length(NEW.forward_profile_sha256)<>32 OR
            sha256(NEW.forward_profile_bytes)<>NEW.forward_profile_sha256 OR
            octet_length(NEW.rollback_profile_bytes)=0 OR
            octet_length(NEW.rollback_profile_sha256)<>32 OR
            sha256(NEW.rollback_profile_bytes)<>NEW.rollback_profile_sha256 OR
            NEW.artifact_size_bytes<=0 OR NEW.rollback_artifact_size_bytes<0)) THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan tuple' USING ERRCODE='P9302';
    END IF;
    BEGIN
        new_snapshot_document := convert_from(NEW.canonical_snapshot_bytes,'UTF8')::jsonb;
        IF NEW.schema_version=2 THEN
            bundle_document := convert_from(NEW.artifact_bundle_bytes,'UTF8')::jsonb;
            forward_profile_document := convert_from(NEW.forward_profile_bytes,'UTF8')::jsonb;
            rollback_profile_document := convert_from(NEW.rollback_profile_bytes,'UTF8')::jsonb;
            rollback_available := (new_snapshot_document->'Safety'->>'RollbackAvailable')::boolean;
        END IF;
        IF TG_OP='UPDATE' THEN
            old_snapshot_document := convert_from(OLD.canonical_snapshot_bytes,'UTF8')::jsonb;
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan snapshot json' USING ERRCODE='P9302';
    END;
    IF jsonb_typeof(new_snapshot_document)<>'object' OR
       new_snapshot_document->>'ID' IS DISTINCT FROM NEW.id::text OR
       new_snapshot_document->'SchemaVersion' IS DISTINCT FROM to_jsonb(NEW.schema_version) OR
       new_snapshot_document->'Revision' IS DISTINCT FROM to_jsonb(NEW.revision) OR
       new_snapshot_document->>'State' IS DISTINCT FROM NEW.state OR
       new_snapshot_document->>'ResumeState' IS DISTINCT FROM NEW.resume_state OR
       new_snapshot_document->>'Completion' IS DISTINCT FROM NEW.completion OR
       new_snapshot_document->'ActiveBatch' IS DISTINCT FROM to_jsonb(NEW.active_batch) OR
       (NEW.schema_version=2 AND (
            new_snapshot_document->>'ParentGrantID' IS DISTINCT FROM NEW.parent_grant_id::text OR
            new_snapshot_document->>'GrantDigest' IS DISTINCT FROM
                translate(rtrim(encode(NEW.parent_grant_sha256,'base64'),'='),'+/','-_') OR
            new_snapshot_document->'ParentGrantExpiresAt' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.parent_grant_expires_at)::bigint) OR
            new_snapshot_document->>'ArtifactBundleID' IS DISTINCT FROM NEW.artifact_bundle_id::text OR
            new_snapshot_document->>'ArtifactBundleSHA256' IS DISTINCT FROM
                translate(rtrim(encode(NEW.artifact_bundle_sha256,'base64'),'='),'+/','-_') OR
            new_snapshot_document->'CommandIssuanceNotAfter' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.command_issuance_not_after)::bigint) OR
            new_snapshot_document->'ForwardProfile' IS DISTINCT FROM forward_profile_document OR
            new_snapshot_document->'RollbackProfile' IS DISTINCT FROM rollback_profile_document OR
            new_snapshot_document->>'ArtifactID' IS DISTINCT FROM
                bundle_document->'bundle'->'forward'->'manifest'->>'artifact_id' OR
            new_snapshot_document->>'SHA256Digest' IS DISTINCT FROM
                bundle_document->'bundle'->'forward'->'manifest'->>'sha256_digest' OR
            new_snapshot_document->'ArtifactSizeBytes' IS DISTINCT FROM to_jsonb(NEW.artifact_size_bytes) OR
            new_snapshot_document->'ArtifactSizeBytes' IS DISTINCT FROM
                bundle_document->'bundle'->'forward'->'manifest'->'artifact_size_bytes' OR
            new_snapshot_document->>'RollbackGrantDigest' IS DISTINCT FROM
                translate(rtrim(encode(NEW.parent_grant_sha256,'base64'),'='),'+/','-_') OR
            new_snapshot_document->>'RollbackArtifactID' IS DISTINCT FROM
                bundle_document->'bundle'->'rollback'->'manifest'->>'artifact_id' OR
            new_snapshot_document->>'RollbackSHA256Digest' IS DISTINCT FROM
                bundle_document->'bundle'->'rollback'->'manifest'->>'sha256_digest' OR
            new_snapshot_document->'RollbackArtifactSizeBytes' IS DISTINCT FROM
                to_jsonb(NEW.rollback_artifact_size_bytes) OR
            new_snapshot_document->'RollbackArtifactSizeBytes' IS DISTINCT FROM
                bundle_document->'bundle'->'rollback'->'manifest'->'artifact_size_bytes' OR
            rollback_available IS NULL OR
            new_snapshot_document->'Safety'->'RollbackAvailable' IS DISTINCT FROM
                to_jsonb(rollback_available) OR
            bundle_document->'bundle'->>'bundle_id' IS DISTINCT FROM NEW.artifact_bundle_id::text OR
            bundle_document->'bundle'->>'plan_id' IS DISTINCT FROM NEW.id::text OR
            bundle_document->'bundle'->'initial_plan_revision' IS DISTINCT FROM '1'::jsonb OR
            bundle_document->'bundle'->>'parent_grant_id' IS DISTINCT FROM NEW.parent_grant_id::text OR
            bundle_document->'bundle'->>'parent_grant_sha256' IS DISTINCT FROM
                translate(rtrim(encode(NEW.parent_grant_sha256,'base64'),'='),'+/','-_') OR
            bundle_document->'bundle'->'parent_grant_expires_at' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.parent_grant_expires_at)::bigint) OR
            bundle_document->'bundle'->>'installation_id' IS DISTINCT FROM NEW.installation_id::text OR
            bundle_document->'bundle'->'channel_revision' IS DISTINCT FROM
                new_snapshot_document->'ReleaseSequence' OR
            bundle_document->'bundle'->>'component' IS DISTINCT FROM
                new_snapshot_document->>'Component' OR
            bundle_document->'bundle'->>'current_version' IS DISTINCT FROM
                new_snapshot_document->>'CurrentVersion' OR
            bundle_document->'bundle'->>'version' IS DISTINCT FROM
                new_snapshot_document->>'TargetVersion' OR
            bundle_document->'bundle'->'forward'->'manifest'->>'component' IS DISTINCT FROM
                new_snapshot_document->>'Component' OR
            bundle_document->'bundle'->'forward'->'manifest'->>'version' IS DISTINCT FROM
                new_snapshot_document->>'TargetVersion' OR
            bundle_document->'bundle'->'rollback'->'manifest'->>'component' IS DISTINCT FROM
                new_snapshot_document->>'Component' OR
            bundle_document->'bundle'->'rollback'->'manifest'->>'version' IS DISTINCT FROM
                new_snapshot_document->>'CurrentVersion' OR
            new_snapshot_document->'RollbackReleaseSequence' IS DISTINCT FROM
                new_snapshot_document->'ReleaseSequence' OR
            bundle_document->'bundle'->'command_issuance_not_after' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.command_issuance_not_after)::bigint) OR
            (rollback_available AND (
                NEW.rollback_artifact_size_bytes<=0 OR
                new_snapshot_document->>'RollbackArtifactID'='' OR
                new_snapshot_document->>'RollbackSHA256Digest'='')) OR
            (NOT rollback_available AND (
                NEW.rollback_artifact_size_bytes<>0 OR
                new_snapshot_document->>'RollbackArtifactID'<>'' OR
                new_snapshot_document->>'RollbackSHA256Digest'<>'')))) THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan snapshot binding' USING ERRCODE='P9302';
    END IF;
    IF TG_OP='UPDATE' AND (
       ROW(NEW.id,NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id,NEW.schema_version,
           NEW.created_at,NEW.parent_grant_id,NEW.parent_grant_bytes,NEW.parent_grant_sha256,
           NEW.parent_grant_expires_at,NEW.artifact_bundle_id,NEW.artifact_bundle_bytes,
           NEW.artifact_bundle_sha256,NEW.command_issuance_not_after,NEW.forward_profile_bytes,NEW.forward_profile_sha256,
           NEW.rollback_profile_bytes,NEW.rollback_profile_sha256,NEW.artifact_size_bytes,
           NEW.rollback_artifact_size_bytes)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.actor_scope_id,OLD.actor_user_id,OLD.installation_id,OLD.schema_version,
           OLD.created_at,OLD.parent_grant_id,OLD.parent_grant_bytes,OLD.parent_grant_sha256,
           OLD.parent_grant_expires_at,OLD.artifact_bundle_id,OLD.artifact_bundle_bytes,
           OLD.artifact_bundle_sha256,OLD.command_issuance_not_after,OLD.forward_profile_bytes,OLD.forward_profile_sha256,
           OLD.rollback_profile_bytes,OLD.rollback_profile_sha256,OLD.artifact_size_bytes,
           OLD.rollback_artifact_size_bytes) OR NEW.revision<=OLD.revision OR
       new_snapshot_document-ARRAY['State','ResumeState','Completion','Revision','ActiveBatch',
           'RollbackBatches','NodeStates','NodeDispatchRevisions','CommandReceipts','HealthReceipts']
       IS DISTINCT FROM
       old_snapshot_document-ARRAY['State','ResumeState','Completion','Revision','ActiveBatch',
           'RollbackBatches','NodeStates','NodeDispatchRevisions','CommandReceipts','HealthReceipts']) THEN
        RAISE EXCEPTION 'invalid upgrade rollout plan mutation' USING ERRCODE='P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_upgrade_command_grant_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    plan_schema smallint;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'control upgrade command grant facts are immutable' USING ERRCODE='P9602';
    END IF;
    SELECT schema_version INTO plan_schema
    FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF NOT FOUND OR plan_schema NOT IN (1,2) THEN
        RAISE EXCEPTION 'control upgrade command requires a bound rollout plan' USING ERRCODE='P9602';
    END IF;
    IF plan_schema=1 AND ROW(NEW.command_grant_bytes,NEW.command_grant_sha256,
       NEW.command_grant_expires_at) IS DISTINCT FROM ROW(NULL,NULL,NULL) THEN
        RAISE EXCEPTION 'schema 1 control upgrade command cannot carry grant facts' USING ERRCODE='P9602';
    ELSIF plan_schema=2 AND (
       octet_length(NEW.command_grant_bytes)=0 OR octet_length(NEW.command_grant_sha256)<>32 OR
       sha256(NEW.command_grant_bytes)<>NEW.command_grant_sha256 OR
       NEW.command_grant_expires_at<=NEW.created_at) THEN
        RAISE EXCEPTION 'invalid control upgrade command grant binding' USING ERRCODE='P9602';
    END IF;
    IF TG_OP='UPDATE' AND ROW(NEW.command_grant_bytes,NEW.command_grant_sha256,
       NEW.command_grant_expires_at) IS DISTINCT FROM ROW(OLD.command_grant_bytes,
       OLD.command_grant_sha256,OLD.command_grant_expires_at) THEN
        RAISE EXCEPTION 'control upgrade command grant facts are immutable' USING ERRCODE='P9602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_upgrade_outbox_ack_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    plan_schema smallint;
BEGIN
    SELECT schema_version INTO plan_schema
    FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF NOT FOUND OR plan_schema NOT IN (1,2) THEN
        RAISE EXCEPTION 'control upgrade outbox requires a bound rollout plan' USING ERRCODE='P9602';
    END IF;
    IF plan_schema=1 AND ROW(NEW.published_stream,NEW.published_sequence)
       IS DISTINCT FROM ROW(NULL,NULL) THEN
        RAISE EXCEPTION 'schema 1 control upgrade outbox cannot carry acknowledgement facts'
            USING ERRCODE='P9602';
    ELSIF plan_schema=2 AND (
       (NEW.state='published' AND (NEW.published_stream IS DISTINCT FROM 'AGENT_COMMANDS' OR
        NEW.published_sequence IS NULL OR NEW.published_sequence<1)) OR
       (NEW.state<>'published' AND (NEW.published_stream IS NOT NULL OR NEW.published_sequence IS NOT NULL))) THEN
        RAISE EXCEPTION 'invalid control upgrade outbox acknowledgement' USING ERRCODE='P9602';
    END IF;
    IF TG_OP='UPDATE' AND ROW(NEW.published_stream,NEW.published_sequence) IS DISTINCT FROM
       ROW(OLD.published_stream,OLD.published_sequence) AND NOT (
        OLD.state='claimed' AND NEW.state='published' AND OLD.published_stream IS NULL AND
        OLD.published_sequence IS NULL AND NEW.published_stream='AGENT_COMMANDS' AND
        NEW.published_sequence>0
       ) THEN
        RAISE EXCEPTION 'control upgrade outbox acknowledgement is immutable' USING ERRCODE='P9602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_upgrade_license_receipt_fact_097(
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
