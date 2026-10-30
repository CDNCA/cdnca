LOCK TABLE schema_migrations,
    control_upgrade_rollout_plans,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_status_receipts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 104 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 104 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=104 AND migration_id='104_background_job_settlement_dlq'
          AND checksum_sha256='fac89e12c1c307327e4855a6cde1366026fb2914605723db14acd980519f3a5e'
          AND down_checksum_sha256='76a85290403d0bddbba56c2245a4391d644b897592d2b2ecb00db8ccf1e8ae12'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 105 requires the exact verified 104 release head'
            USING ERRCODE='P1050';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_status_validate_093 ON control_upgrade_status_receipts;
DROP TRIGGER control_upgrade_status_semantics_096 ON control_upgrade_status_receipts;

CREATE FUNCTION validate_control_upgrade_status_105()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_row control_upgrade_node_commands%ROWTYPE;
    command_payload_sha bytea;
    outbox_state text;
    status_document jsonb;
    evidence_document jsonb;
    status_field_count bigint;
    evidence_field_count bigint;
    previous_revision bigint;
    previous_state text;
    previous_observed_at timestamptz;
    previous_status_document jsonb;
    installer_transaction_id text;
    evidence_canonical text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'upgrade status receipts are immutable facts' USING ERRCODE='P9302';
    END IF;
    IF NEW.status_revision < 1 OR octet_length(NEW.status_bytes)=0 OR
       octet_length(NEW.status_sha256)<>32 OR sha256(NEW.status_bytes)<>NEW.status_sha256 OR
       octet_length(NEW.command_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid upgrade status tuple' USING ERRCODE='P9302';
    END IF;
    SELECT * INTO command_row FROM control_upgrade_node_commands
    WHERE command_id=NEW.command_id FOR UPDATE;
    IF NOT FOUND OR ROW(NEW.plan_id,NEW.plan_revision,NEW.batch_id,NEW.actor_scope_id,
       NEW.actor_user_id,NEW.installation_id,NEW.node_id,NEW.action) IS DISTINCT FROM
       ROW(command_row.plan_id,command_row.plan_revision,command_row.batch_id,
       command_row.actor_scope_id,command_row.actor_user_id,command_row.installation_id,
       command_row.node_id,command_row.action) OR
       command_row.state NOT IN ('published','acknowledged') OR command_row.published_at IS NULL OR
       NEW.observed_at<command_row.published_at OR
       NEW.observed_at>transaction_timestamp()+interval '30 seconds' THEN
        RAISE EXCEPTION 'invalid upgrade status binding' USING ERRCODE='P9302';
    END IF;
    SELECT payload_sha256,state INTO command_payload_sha,outbox_state
    FROM control_upgrade_outbox WHERE command_id=NEW.command_id FOR UPDATE;
    IF NOT FOUND OR outbox_state<>'published' OR NEW.command_sha256<>command_payload_sha THEN
        RAISE EXCEPTION 'invalid upgrade status command digest' USING ERRCODE='P9302';
    END IF;

    BEGIN
        status_document := convert_from(NEW.status_bytes,'UTF8')::jsonb;
        SELECT count(*) INTO status_field_count FROM jsonb_object_keys(status_document);
        installer_transaction_id := status_document->>'installer_transaction_id';
        IF jsonb_typeof(status_document)<>'object' OR
           jsonb_typeof(status_document->'schema')<>'string' OR
           status_document->>'schema' NOT IN ('cdnca.edge.upgrade.status/v1','cdnca.edge.upgrade.status/v2') OR
           (status_document->>'schema'='cdnca.edge.upgrade.status/v1' AND
            (status_field_count<>16 OR status_document ? 'active_evidence')) OR
           (status_document->>'schema'='cdnca.edge.upgrade.status/v2' AND
            (status_field_count<>17 OR NOT status_document ? 'active_evidence')) OR NOT
           (status_document ?& ARRAY['schema','status_id','status_revision','command_id','plan_id',
            'plan_revision','installation_id','node_id','command_sha256','state','current_version',
            'previous_version','installer_transaction_id','error_code','alert_required','observed_at']) OR
           status_document ? 'batch_id' OR status_document ? 'action' OR
           status_document->>'status_id' IS DISTINCT FROM NEW.status_id::text OR
           status_document->'status_revision' IS DISTINCT FROM to_jsonb(NEW.status_revision) OR
           status_document->>'command_id' IS DISTINCT FROM NEW.command_id::text OR
           status_document->>'plan_id' IS DISTINCT FROM NEW.plan_id::text OR
           status_document->'plan_revision' IS DISTINCT FROM to_jsonb(NEW.plan_revision) OR
           status_document->>'installation_id' IS DISTINCT FROM NEW.installation_id::text OR
           status_document->>'node_id' IS DISTINCT FROM NEW.node_id::text OR
           status_document->>'command_sha256' IS DISTINCT FROM encode(command_payload_sha,'hex') OR
           status_document->>'state' IS DISTINCT FROM NEW.state OR
           jsonb_typeof(status_document->'current_version')<>'string' OR
           jsonb_typeof(status_document->'previous_version')<>'string' OR
           jsonb_typeof(status_document->'installer_transaction_id')<>'string' OR
           jsonb_typeof(status_document->'error_code')<>'string' OR
           jsonb_typeof(status_document->'alert_required')<>'boolean' OR
           (status_document->>'observed_at')::timestamptz IS DISTINCT FROM NEW.observed_at OR
           (installer_transaction_id<>'' AND
            installer_transaction_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
           (status_document->>'error_code'<>'' AND
            status_document->>'error_code' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') THEN
            RAISE EXCEPTION 'invalid upgrade status document' USING ERRCODE='P9302';
        END IF;

        IF status_document->>'schema'='cdnca.edge.upgrade.status/v2' AND
           NEW.state IN ('healthy','rolled_back') THEN
            evidence_document := status_document->'active_evidence';
            SELECT count(*) INTO evidence_field_count FROM jsonb_object_keys(evidence_document);
            IF jsonb_typeof(evidence_document)<>'object' OR evidence_field_count<>8 OR NOT
               (evidence_document ?& ARRAY['schema','active_artifact_sha256','active_config_sha256',
                'last_known_good_artifact_sha256','last_known_good_config_sha256',
                'probe_observed_at','probe_deadline','evidence_sha256']) OR
               evidence_document->>'schema' IS DISTINCT FROM 'cdnca.edge.upgrade.active-probe/v1' OR
               evidence_document->>'active_artifact_sha256' !~ '^[0-9a-f]{64}$' OR
               evidence_document->>'active_config_sha256' !~ '^[0-9a-f]{64}$' OR
               evidence_document->>'last_known_good_artifact_sha256' !~ '^[0-9a-f]{64}$' OR
               evidence_document->>'last_known_good_config_sha256' !~ '^[0-9a-f]{64}$' OR
               evidence_document->>'evidence_sha256' !~ '^[0-9a-f]{64}$' OR
		       (evidence_document->>'probe_observed_at')::timestamptz>
		           (evidence_document->>'probe_deadline')::timestamptz OR
		       (evidence_document->>'probe_observed_at')::timestamptz>NEW.observed_at THEN
                RAISE EXCEPTION 'invalid upgrade active probe evidence' USING ERRCODE='P9302';
            END IF;
            evidence_canonical :=
                '{"schema":'||to_json(evidence_document->>'schema')::text||
                ',"active_artifact_sha256":'||to_json(evidence_document->>'active_artifact_sha256')::text||
                ',"active_config_sha256":'||to_json(evidence_document->>'active_config_sha256')::text||
                ',"last_known_good_artifact_sha256":'||to_json(evidence_document->>'last_known_good_artifact_sha256')::text||
                ',"last_known_good_config_sha256":'||to_json(evidence_document->>'last_known_good_config_sha256')::text||
                ',"installer_transaction_id":'||to_json(installer_transaction_id)::text||
                ',"probe_observed_at":'||to_json(evidence_document->>'probe_observed_at')::text||
                ',"probe_deadline":'||to_json(evidence_document->>'probe_deadline')::text||'}';
            IF encode(sha256(convert_to(evidence_canonical,'UTF8')),'hex') IS DISTINCT FROM
               evidence_document->>'evidence_sha256' THEN
                RAISE EXCEPTION 'invalid upgrade active probe evidence digest' USING ERRCODE='P9302';
            END IF;
        ELSIF status_document->>'schema'='cdnca.edge.upgrade.status/v2' AND
              jsonb_typeof(status_document->'active_evidence') IS DISTINCT FROM 'null' THEN
            RAISE EXCEPTION 'non-active upgrade status contains active probe evidence' USING ERRCODE='P9302';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9302' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid upgrade status json' USING ERRCODE='P9302';
    END;

    SELECT status_revision,state,observed_at,
           convert_from(status_bytes,'UTF8')::jsonb
    INTO previous_revision,previous_state,previous_observed_at,previous_status_document
    FROM control_upgrade_status_receipts WHERE command_id=NEW.command_id
    ORDER BY status_revision DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.status_revision<>1 OR NEW.state NOT IN ('accepted','claimed') THEN
            RAISE EXCEPTION 'invalid initial upgrade status' USING ERRCODE='P9302';
        END IF;
    ELSIF NEW.status_revision<>previous_revision+1 OR NEW.observed_at<previous_observed_at OR NOT (
       (previous_state='accepted' AND NEW.state='claimed') OR
       (previous_state='claimed' AND NEW.state='installing') OR
       (previous_state='installing' AND command_row.action='upgrade' AND
        NEW.state IN ('healthy','failed','rolling_back','uncertain')) OR
       (previous_state='installing' AND command_row.action='rollback' AND
        NEW.state IN ('failed','rolled_back','uncertain')) OR
       (previous_state='rolling_back' AND command_row.action='upgrade' AND
        NEW.state IN ('rolled_back','uncertain')) OR
       (previous_state='uncertain' AND command_row.action='upgrade' AND
        NEW.state IN ('uncertain','healthy','failed','rolled_back')) OR
       (previous_state='uncertain' AND command_row.action='rollback' AND
        NEW.state IN ('uncertain','failed','rolled_back'))
    ) THEN
        RAISE EXCEPTION 'invalid upgrade status transition' USING ERRCODE='P9302';
    END IF;
    IF previous_state IN ('installing','rolling_back','uncertain') AND
       (previous_status_document->>'installer_transaction_id'='' OR
        installer_transaction_id IS DISTINCT FROM previous_status_document->>'installer_transaction_id') THEN
        RAISE EXCEPTION 'invalid upgrade status transaction continuity' USING ERRCODE='P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_upgrade_status_semantics_105()
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

CREATE TRIGGER control_upgrade_status_validate_105
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_105();

CREATE TRIGGER control_upgrade_status_semantics_105
BEFORE INSERT ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_semantics_105();

REVOKE ALL ON FUNCTION validate_control_upgrade_status_105() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_status_semantics_105() FROM PUBLIC;
