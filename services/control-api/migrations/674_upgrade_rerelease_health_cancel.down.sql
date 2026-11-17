-- 674 回退：计划触发器回到 672 版、状态语义函数回到 105 版、写回执 operation 去掉 cancel。
-- 存在同版本重出计划（旧函数会拒绝其 healthy 回执）或 cancelled 计划（旧触发器不认该状态）时拒绝回退。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE control_upgrade_write_receipts_096 IN ACCESS EXCLUSIVE MODE;
LOCK TABLE control_upgrade_rollout_plans, control_upgrade_status_receipts IN SHARE ROW EXCLUSIVE MODE;

DO $migration_674_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 674 OR
       (SELECT max(version) FROM schema_migrations) <> 674 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=674 AND
        migration_id='674_upgrade_rerelease_health_cancel' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 674 down requires the exact verified migration head' USING ERRCODE='P6741';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_upgrade_rollout_plans WHERE state='cancelled' OR
            convert_from(canonical_snapshot_bytes,'UTF8')::jsonb ? 'CurrentReleaseSequence'
       ) OR EXISTS (SELECT 1 FROM control_upgrade_write_receipts_096 WHERE operation='cancel') THEN
        RAISE EXCEPTION 'migration 674 rollback would strand same-version re-release or cancelled upgrade plans'
            USING ERRCODE='P6742';
    END IF;
END;
$migration_674_down$;

ALTER TABLE control_upgrade_write_receipts_096
    DROP CONSTRAINT control_upgrade_write_receipts_096_operation_674,
    ADD CONSTRAINT control_upgrade_write_receipts_096_operation_check CHECK (
        operation IN ('create','start','pause','resume','rollback'));

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
    forward_sequence numeric;
    rollback_sequence numeric;
    current_sequence numeric;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'upgrade rollout plans are immutable facts' USING ERRCODE='P9302';
    END IF;
    IF NEW.schema_version NOT IN (1,2,3) OR NEW.revision<1 OR NEW.active_batch< -1 OR
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
       (NEW.schema_version IN (2,3) AND (
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
        IF NEW.schema_version IN (2,3) THEN
            bundle_document := convert_from(NEW.artifact_bundle_bytes,'UTF8')::jsonb;
            forward_profile_document := convert_from(NEW.forward_profile_bytes,'UTF8')::jsonb;
            rollback_profile_document := convert_from(NEW.rollback_profile_bytes,'UTF8')::jsonb;
            rollback_available := (new_snapshot_document->'Safety'->>'RollbackAvailable')::boolean;
        END IF;
        IF NEW.schema_version=3 THEN
            -- jsonb null 或非数字直接抛错转 P9302；缺键为 SQL NULL，由下方绑定检查拒绝。
            forward_sequence := (new_snapshot_document->'ReleaseSequence')::numeric;
            rollback_sequence := (new_snapshot_document->'RollbackReleaseSequence')::numeric;
            current_sequence := (new_snapshot_document->'CurrentReleaseSequence')::numeric;
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
                new_snapshot_document->>'RollbackSHA256Digest'<>'')))) OR
       (NEW.schema_version=3 AND (
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
            rollback_available IS NULL OR
            new_snapshot_document->'Safety'->'RollbackAvailable' IS DISTINCT FROM
                to_jsonb(rollback_available) OR
            bundle_document->'bundle'->>'schema' IS DISTINCT FROM 'cdnca.upgrade.plan-artifact-bundle/v2' OR
            bundle_document->'bundle'->'forward'->'manifest'->>'schema' IS DISTINCT FROM 'cdnca.release.artifact/v3' OR
            bundle_document->'bundle'->'rollback'->'manifest'->>'schema' IS DISTINCT FROM 'cdnca.release.artifact/v3' OR
            bundle_document->'bundle'->>'bundle_id' IS DISTINCT FROM NEW.artifact_bundle_id::text OR
            bundle_document->'bundle'->>'plan_id' IS DISTINCT FROM NEW.id::text OR
            bundle_document->'bundle'->'initial_plan_revision' IS DISTINCT FROM '1'::jsonb OR
            bundle_document->'bundle'->>'parent_grant_id' IS DISTINCT FROM NEW.parent_grant_id::text OR
            bundle_document->'bundle'->>'parent_grant_sha256' IS DISTINCT FROM
                translate(rtrim(encode(NEW.parent_grant_sha256,'base64'),'='),'+/','-_') OR
            bundle_document->'bundle'->'parent_grant_expires_at' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.parent_grant_expires_at)::bigint) OR
            bundle_document->'bundle'->>'installation_id' IS DISTINCT FROM NEW.installation_id::text OR
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
            bundle_document->'bundle'->'command_issuance_not_after' IS DISTINCT FROM
                to_jsonb(extract(epoch from NEW.command_issuance_not_after)::bigint) OR
            -- v3：ReleaseSequence 是前向清单的物理序号（v2 绑的是 channel_revision）。
            new_snapshot_document->'ReleaseSequence' IS DISTINCT FROM
                bundle_document->'bundle'->'forward'->'manifest'->'release_sequence' OR
            forward_sequence IS NULL OR forward_sequence<1 OR rollback_sequence IS NULL OR
            -- 跨版本升级：回滚到旧构建，回滚序号必须低于前向序号。
            (current_sequence IS NULL AND (
                bundle_document->'bundle' ? 'current_release_sequence' OR
                bundle_document->'bundle'->>'current_version' IS NOT DISTINCT FROM
                    bundle_document->'bundle'->>'version' OR
                rollback_available IS NOT TRUE OR
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
                NEW.rollback_artifact_size_bytes<=0 OR
                new_snapshot_document->'RollbackReleaseSequence' IS DISTINCT FROM
                    bundle_document->'bundle'->'rollback'->'manifest'->'release_sequence' OR
                rollback_sequence<1 OR rollback_sequence>=forward_sequence)) OR
            -- 同版本重出：注册表只有一份该版本构建，前向=回滚清单，计划没有控制面回滚。
            (current_sequence IS NOT NULL AND (
                current_sequence<1 OR
                bundle_document->'bundle'->'current_release_sequence' IS DISTINCT FROM
                    new_snapshot_document->'CurrentReleaseSequence' OR
                bundle_document->'bundle'->>'current_version' IS DISTINCT FROM
                    bundle_document->'bundle'->>'version' OR
                bundle_document->'bundle'->'forward' IS DISTINCT FROM
                    bundle_document->'bundle'->'rollback' OR
                forward_sequence<=current_sequence OR
                rollback_available IS NOT FALSE OR
                new_snapshot_document->>'RollbackGrantDigest' IS DISTINCT FROM '' OR
                new_snapshot_document->>'RollbackArtifactID' IS DISTINCT FROM '' OR
                new_snapshot_document->>'RollbackSHA256Digest' IS DISTINCT FROM '' OR
                new_snapshot_document->'RollbackArtifactSizeBytes' IS DISTINCT FROM '0'::jsonb OR
                NEW.rollback_artifact_size_bytes IS DISTINCT FROM 0 OR
                rollback_sequence<>0)))) THEN
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

CREATE OR REPLACE FUNCTION validate_control_upgrade_status_semantics_105()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_row control_upgrade_node_commands%ROWTYPE;
    plan_snapshot jsonb;
    status_document jsonb;
    evidence_document jsonb;
    previous_state text;
    rolling_back_document jsonb;
    rollback_trigger_error text;
    installer_transaction_id text;
BEGIN
    SELECT * INTO command_row FROM control_upgrade_node_commands
    WHERE command_id=NEW.command_id FOR SHARE;
    SELECT convert_from(canonical_snapshot_bytes,'UTF8')::jsonb INTO plan_snapshot
    FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF command_row.command_id IS NULL OR plan_snapshot IS NULL THEN
        RAISE EXCEPTION 'invalid upgrade status semantic authority' USING ERRCODE='P9302';
    END IF;
    status_document := convert_from(NEW.status_bytes,'UTF8')::jsonb;
    installer_transaction_id := status_document->>'installer_transaction_id';
    SELECT state INTO previous_state FROM control_upgrade_status_receipts
    WHERE command_id=NEW.command_id ORDER BY status_revision DESC LIMIT 1;

    IF command_row.action='upgrade' AND NEW.state='rolled_back' THEN
        SELECT convert_from(status_bytes,'UTF8')::jsonb INTO rolling_back_document
        FROM control_upgrade_status_receipts
        WHERE command_id=NEW.command_id AND state='rolling_back' AND status_revision<NEW.status_revision
        ORDER BY status_revision DESC LIMIT 1;
        IF rolling_back_document IS NOT NULL THEN
            rollback_trigger_error := rolling_back_document->>'error_code';
            IF rollback_trigger_error='' THEN
                RAISE EXCEPTION 'invalid rolling back trigger error' USING ERRCODE='P9302';
            END IF;
        END IF;
    END IF;

    IF (NEW.state IN ('accepted','claimed') AND (
           status_document->>'current_version'<>'' OR status_document->>'previous_version'<>'' OR
           installer_transaction_id<>'' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (NEW.state='installing' AND (
           status_document->>'current_version'<>'' OR status_document->>'previous_version'<>'' OR
           installer_transaction_id='' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command_row.action='upgrade' AND NEW.state='rolling_back' AND (
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'='' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (NEW.state='healthy' AND (
           command_row.action<>'upgrade' OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command_row.action='upgrade' AND NEW.state='rolled_back' AND (
           previous_state NOT IN ('rolling_back','uncertain') OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'='' OR
           (rollback_trigger_error IS NOT NULL AND
            status_document->>'error_code' IS DISTINCT FROM rollback_trigger_error) OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command_row.action='rollback' AND NEW.state='rolled_back' AND (
           previous_state NOT IN ('installing','uncertain') OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (NEW.state='failed' AND (
           command_row.action NOT IN ('upgrade','rollback') OR
           status_document->>'error_code' IN ('','ROLLBACK_FAILED') OR installer_transaction_id='' OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           (command_row.action='upgrade' AND status_document->>'previous_version'<>'') OR
           (command_row.action='rollback' AND
            status_document->>'previous_version' NOT IN ('',plan_snapshot->>'TargetVersion')) OR
           status_document->'alert_required' IS DISTINCT FROM 'true'::jsonb)) OR
       (NEW.state='uncertain' AND (
           installer_transaction_id='' OR status_document->>'error_code'='' OR NOT (
             (status_document->>'current_version'='' AND status_document->>'previous_version'='') OR
             (status_document->>'current_version' IS NOT DISTINCT FROM plan_snapshot->>'TargetVersion' AND
              status_document->>'previous_version' IS NOT DISTINCT FROM plan_snapshot->>'CurrentVersion')) OR
           status_document->'alert_required' IS DISTINCT FROM 'true'::jsonb)) THEN
        RAISE EXCEPTION 'invalid upgrade status semantic binding' USING ERRCODE='P9302';
    END IF;

    IF status_document->>'schema'='cdnca.edge.upgrade.status/v2' AND
       NEW.state IN ('healthy','rolled_back') THEN
        evidence_document := status_document->'active_evidence';
        IF (NEW.state='healthy' AND (
             evidence_document->>'active_artifact_sha256' IS DISTINCT FROM encode(decode(
                rpad(translate(plan_snapshot->>'SHA256Digest','-_','+/'),44,'='),'base64'),'hex') OR
             evidence_document->>'last_known_good_artifact_sha256' IS DISTINCT FROM
                encode(decode(rpad(translate(plan_snapshot->>'RollbackSHA256Digest','-_','+/'),44,'='),
                'base64'),'hex'))) OR
           (NEW.state='rolled_back' AND (
             evidence_document->>'active_artifact_sha256' IS DISTINCT FROM
                encode(decode(rpad(translate(plan_snapshot->>'RollbackSHA256Digest','-_','+/'),44,'='),
                'base64'),'hex') OR
             evidence_document->>'last_known_good_artifact_sha256' IS DISTINCT FROM
                encode(decode(rpad(translate(plan_snapshot->>'SHA256Digest','-_','+/'),44,'='),
                'base64'),'hex'))) THEN
            RAISE EXCEPTION 'upgrade active probe artifact evidence does not match plan'
                USING ERRCODE='P9302';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
