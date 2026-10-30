LOCK TABLE schema_migrations,
    permissions,
    roles,
    role_permissions,
    audit_events,
    control_upgrade_rbac_grant_additions_096,
    control_upgrade_grant_intents_096,
    control_upgrade_write_receipts_096,
    control_upgrade_outbox_rejections_096,
    control_upgrade_status_rejections_096,
    control_upgrade_rollout_plans,
    control_upgrade_rollout_events,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_status_receipts
IN ACCESS EXCLUSIVE MODE;

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
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 096 rollback requires the exact verified 096 head'
            USING ERRCODE='P9600';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=95 AND migration_id='095_security_activation'
          AND checksum_sha256='a3f87e9b0e29162e86e2011a26961a78b424ab2c0f5d20dd6a8d6827a2d81ecf'
          AND down_checksum_sha256='b6a86ba075f7b53b913ac99e3b59774bb6c0213b43d47cf9eeec9273a50d34bb'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 096 rollback requires the exact verified 095 parent'
            USING ERRCODE='P9600';
    END IF;
    IF EXISTS (SELECT 1 FROM control_upgrade_grant_intents_096) OR
       EXISTS (SELECT 1 FROM control_upgrade_write_receipts_096) OR
       EXISTS (SELECT 1 FROM control_upgrade_outbox_rejections_096) OR
       EXISTS (SELECT 1 FROM control_upgrade_status_rejections_096) OR
       EXISTS (
           SELECT 1 FROM control_upgrade_rollout_plans
           WHERE schema_version=2 OR parent_grant_id IS NOT NULL OR parent_grant_bytes IS NOT NULL OR
                 parent_grant_sha256 IS NOT NULL OR parent_grant_expires_at IS NOT NULL OR
                 artifact_bundle_id IS NOT NULL OR artifact_bundle_bytes IS NOT NULL OR
                 artifact_bundle_sha256 IS NOT NULL OR command_issuance_not_after IS NOT NULL OR
                 forward_profile_bytes IS NOT NULL OR forward_profile_sha256 IS NOT NULL OR
                 rollback_profile_bytes IS NOT NULL OR rollback_profile_sha256 IS NOT NULL OR
                 artifact_size_bytes IS NOT NULL OR rollback_artifact_size_bytes IS NOT NULL
       ) OR EXISTS (
           SELECT 1 FROM control_upgrade_node_commands
           WHERE command_grant_bytes IS NOT NULL OR command_grant_sha256 IS NOT NULL OR
                 command_grant_expires_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 096 rollback would discard control upgrade runtime facts'
            USING ERRCODE = 'P9601';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_write_receipt_audit_096 ON control_upgrade_write_receipts_096;
DROP TRIGGER control_upgrade_write_receipt_append_only_096 ON control_upgrade_write_receipts_096;
DROP TRIGGER control_upgrade_rejection_append_only_096 ON control_upgrade_outbox_rejections_096;
DROP TRIGGER control_upgrade_status_rejection_append_only_096 ON control_upgrade_status_rejections_096;
DROP TRIGGER control_upgrade_write_receipt_no_truncate_096 ON control_upgrade_write_receipts_096;
DROP TRIGGER control_upgrade_rejection_no_truncate_096 ON control_upgrade_outbox_rejections_096;
DROP TRIGGER control_upgrade_status_rejection_no_truncate_096 ON control_upgrade_status_rejections_096;
DROP TRIGGER control_upgrade_grant_intent_consumed_096 ON control_upgrade_grant_intents_096;
DROP TRIGGER control_upgrade_grant_intent_validate_096 ON control_upgrade_grant_intents_096;
DROP TRIGGER control_upgrade_grant_intent_no_truncate_096 ON control_upgrade_grant_intents_096;
DROP TRIGGER control_upgrade_outbox_ack_validate_096 ON control_upgrade_outbox;
DROP TRIGGER control_upgrade_command_grant_validate_096 ON control_upgrade_node_commands;
DROP TRIGGER control_upgrade_status_semantics_096 ON control_upgrade_status_receipts;
DROP TRIGGER roles_project_control_upgrade_permissions_096 ON roles;
DROP TRIGGER role_permissions_guard_control_upgrade_096 ON role_permissions;

DROP INDEX control_upgrade_denied_audit_096;

DROP TABLE control_upgrade_outbox_rejections_096;
DROP TABLE control_upgrade_status_rejections_096;
DROP TABLE control_upgrade_write_receipts_096;
DROP TABLE control_upgrade_grant_intents_096;

CREATE OR REPLACE FUNCTION validate_control_upgrade_plan_093()
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

ALTER TABLE control_upgrade_node_commands
    DROP COLUMN command_grant_expires_at,
    DROP COLUMN command_grant_sha256,
    DROP COLUMN command_grant_bytes;

ALTER TABLE control_upgrade_outbox
    DROP COLUMN published_sequence,
    DROP COLUMN published_stream;

ALTER TABLE control_upgrade_rollout_plans
    DROP COLUMN rollback_artifact_size_bytes,
    DROP COLUMN artifact_size_bytes,
    DROP COLUMN rollback_profile_sha256,
    DROP COLUMN rollback_profile_bytes,
    DROP COLUMN forward_profile_sha256,
    DROP COLUMN forward_profile_bytes,
    DROP COLUMN command_issuance_not_after,
    DROP COLUMN artifact_bundle_sha256,
    DROP COLUMN artifact_bundle_bytes,
    DROP COLUMN artifact_bundle_id,
    DROP COLUMN parent_grant_expires_at,
    DROP COLUMN parent_grant_sha256,
    DROP COLUMN parent_grant_bytes,
    DROP COLUMN parent_grant_id;

DROP FUNCTION validate_control_upgrade_write_receipt_096();
DROP FUNCTION validate_control_upgrade_consumed_intent_096();
DROP FUNCTION validate_control_upgrade_grant_intent_096();
DROP FUNCTION validate_control_upgrade_runtime_fact_096();
DROP FUNCTION validate_control_upgrade_command_grant_096();
DROP FUNCTION validate_control_upgrade_outbox_ack_096();
DROP FUNCTION validate_control_upgrade_status_semantics_096();

ALTER TABLE control_upgrade_rbac_grant_additions_096
    DISABLE TRIGGER control_upgrade_rbac_provenance_row_096;
ALTER TABLE control_upgrade_rbac_grant_additions_096
    DISABLE TRIGGER control_upgrade_rbac_provenance_truncate_096;

DELETE FROM role_permissions permission
USING control_upgrade_rbac_grant_additions_096 addition
WHERE permission.role_id=addition.role_id AND permission.permission_name=addition.permission_name;

DROP TRIGGER control_upgrade_rbac_provenance_row_096 ON control_upgrade_rbac_grant_additions_096;
DROP TRIGGER control_upgrade_rbac_provenance_truncate_096 ON control_upgrade_rbac_grant_additions_096;
DROP TABLE control_upgrade_rbac_grant_additions_096;

DROP FUNCTION protect_control_upgrade_rbac_provenance_096();
DROP FUNCTION project_control_upgrade_permissions_096();
DROP FUNCTION guard_control_upgrade_permissions_096();

DELETE FROM permissions
WHERE name IN ('control.upgrades.read','control.upgrades.manage');
