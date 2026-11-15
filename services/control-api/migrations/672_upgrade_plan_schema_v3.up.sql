-- 672（节点升级计划 schema 3 可入库）；前驱 671_system_settings_kyc_object_secrets。
-- 既有缺陷：controlupgrade.RolloutPlanSchemaVersion=3（RollbackReleaseSequence<>ReleaseSequence 或同版本重出
-- CurrentReleaseSequence>0 时计划用 v3），但 096 的计划触发器只认 schema 1/2、命令授权与投递确认触发器只认
-- 计划 schema 1/2，097 授权端回执只认计划 schema 2。授权端现发 plan-artifact-bundle/v2 + release.artifact/v3，
-- 跨版本升级与同版本重出的计划都是 v3，FinalizeCreateRollout 必报 P9302。
-- 本迁移重写这四个函数：v1/v2 分支逐字保留；新增 v3 分支按 plan.go v3 文档严格校验：
--   计划包必须 v2、两份清单必须 v3；ReleaseSequence=前向清单 release_sequence；
--   跨版本：无 CurrentReleaseSequence、RollbackAvailable=true、回滚字段=回滚清单、0<RollbackReleaseSequence<ReleaseSequence；
--   同版本重出：CurrentReleaseSequence=计划包 current_release_sequence>0、前向=回滚清单、
--     ReleaseSequence>CurrentReleaseSequence、RollbackAvailable=false 且回滚字段全空/0；
--   命令授权：必须 command-grant/v3，release_sequence 按动作对上计划，current_release_sequence 与计划一致，
--     同版本重出计划不接受 rollback 命令。
-- 错误码沿用：计划 P9302、命令/投递确认 P9602、回执 P9702（函数返回 false 由原触发器抛）；头检查 P6720。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE control_upgrade_rollout_plans,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_license_receipt_outbox_097
IN SHARE ROW EXCLUSIVE MODE;

DO $migration_672_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 671 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 671 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=671 AND
        migration_id='671_system_settings_kyc_object_secrets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('validate_control_upgrade_plan_093()') IS NULL OR
       to_regprocedure('validate_control_upgrade_command_grant_096()') IS NULL OR
       to_regprocedure('validate_control_upgrade_outbox_ack_096()') IS NULL OR
       EXISTS (SELECT 1 FROM control_upgrade_rollout_plans WHERE schema_version NOT IN (1,2)) THEN
        RAISE EXCEPTION 'migration 672 requires the exact verified 671 release head' USING ERRCODE='P6720';
    END IF;
END;
$migration_672_up$;

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

CREATE OR REPLACE FUNCTION validate_control_upgrade_command_grant_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    plan_schema smallint;
    plan_snapshot bytea;
    plan_document jsonb;
    grant_document jsonb;
    execution_document jsonb;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'control upgrade command grant facts are immutable' USING ERRCODE='P9602';
    END IF;
    SELECT schema_version,canonical_snapshot_bytes INTO plan_schema,plan_snapshot
    FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF NOT FOUND OR plan_schema NOT IN (1,2,3) THEN
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
    ELSIF plan_schema=3 THEN
        BEGIN
            plan_document := convert_from(plan_snapshot,'UTF8')::jsonb;
            grant_document := convert_from(NEW.command_grant_bytes,'UTF8')::jsonb;
            execution_document := convert_from(NEW.signed_execution_bytes,'UTF8')::jsonb;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid control upgrade command grant binding' USING ERRCODE='P9602';
        END;
        -- 列 command_schema/release_sequence/component 与签名文档的一致性由 101 触发器负责；
        -- 这里把它们绑到计划：前向命令=ReleaseSequence，回滚命令=RollbackReleaseSequence，
        -- 同版本重出计划（有 CurrentReleaseSequence）没有控制面回滚。
        IF octet_length(NEW.command_grant_bytes)=0 OR octet_length(NEW.command_grant_sha256)<>32 OR
           sha256(NEW.command_grant_bytes)<>NEW.command_grant_sha256 OR
           NEW.command_grant_expires_at<=NEW.created_at OR
           NEW.command_schema IS DISTINCT FROM 'cdnca.upgrade.command-grant/v3' OR
           NEW.component IS DISTINCT FROM plan_document->>'Component' OR
           NEW.action NOT IN ('upgrade','rollback') OR
           (NEW.action='upgrade' AND
            NEW.release_sequence::text IS DISTINCT FROM plan_document->>'ReleaseSequence') OR
           (NEW.action='rollback' AND (plan_document ? 'CurrentReleaseSequence' OR
            NEW.release_sequence::text IS DISTINCT FROM plan_document->>'RollbackReleaseSequence')) OR
           grant_document#>>'{grant,current_release_sequence}' IS DISTINCT FROM
               plan_document->>'CurrentReleaseSequence' OR
           execution_document#>>'{execution,current_release_sequence}' IS DISTINCT FROM
               plan_document->>'CurrentReleaseSequence' THEN
            RAISE EXCEPTION 'invalid control upgrade v3 command grant binding' USING ERRCODE='P9602';
        END IF;
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
    IF NOT FOUND OR plan_schema NOT IN (1,2,3) THEN
        RAISE EXCEPTION 'control upgrade outbox requires a bound rollout plan' USING ERRCODE='P9602';
    END IF;
    IF plan_schema=1 AND ROW(NEW.published_stream,NEW.published_sequence)
       IS DISTINCT FROM ROW(NULL,NULL) THEN
        RAISE EXCEPTION 'schema 1 control upgrade outbox cannot carry acknowledgement facts'
            USING ERRCODE='P9602';
    ELSIF plan_schema IN (2,3) AND (
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
    IF NOT FOUND OR plan_record.schema_version NOT IN (2,3) OR
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
