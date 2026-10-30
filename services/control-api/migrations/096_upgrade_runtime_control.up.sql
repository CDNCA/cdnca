LOCK TABLE schema_migrations,
    permissions,
    roles,
    role_permissions,
    audit_events,
    control_upgrade_rollout_plans,
    control_upgrade_rollout_events,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_status_receipts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 95 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 95 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 95
          AND migration_id = '095_security_activation'
          AND checksum_sha256 = 'a3f87e9b0e29162e86e2011a26961a78b424ab2c0f5d20dd6a8d6827a2d81ecf'
          AND down_checksum_sha256 = 'b6a86ba075f7b53b913ac99e3b59774bb6c0213b43d47cf9eeec9273a50d34bb'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 096 requires the exact verified 095 release head'
            USING ERRCODE = 'P9600';
    END IF;
END;
$$;

INSERT INTO permissions(name, description) VALUES
    ('control.upgrades.read', 'Read platform control upgrade rollouts'),
    ('control.upgrades.manage', 'Create and operate platform control upgrade rollouts');

CREATE TABLE control_upgrade_rbac_grant_additions_096 (
    role_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (
        permission_name IN ('control.upgrades.read','control.upgrades.manage')
    ),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (scope_id, role_id) REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT
);

CREATE FUNCTION guard_control_upgrade_permissions_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_role_id uuid;
    target_permission text;
    target_scope_kind text;
    target_system_role boolean;
    target_role_name text;
BEGIN
    target_role_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END;
    target_permission := CASE WHEN TG_OP = 'DELETE' THEN OLD.permission_name ELSE NEW.permission_name END;
    IF target_permission NOT IN ('control.upgrades.read','control.upgrades.manage') THEN
        IF TG_OP='DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT scope.kind, role.system_role, role.name
      INTO target_scope_kind, target_system_role, target_role_name
    FROM roles role JOIN access_scopes scope ON scope.id=role.scope_id
    WHERE role.id=target_role_id FOR SHARE;
    IF target_scope_kind IS DISTINCT FROM 'platform' OR
       target_system_role IS DISTINCT FROM true OR
       target_role_name IS DISTINCT FROM 'platform_owner' THEN
        RAISE EXCEPTION 'control upgrade permissions are restricted to platform_owner'
            USING ERRCODE = 'P9602';
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER role_permissions_guard_control_upgrade_096
BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION guard_control_upgrade_permissions_096();

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, permission.permission_name
    FROM roles role
    JOIN access_scopes scope ON scope.id=role.scope_id
    CROSS JOIN (VALUES ('control.upgrades.read'),('control.upgrades.manage')) permission(permission_name)
    WHERE role.system_role AND scope.kind='platform' AND role.name='platform_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO control_upgrade_rbac_grant_additions_096(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id=addition.role_id;

CREATE FUNCTION project_control_upgrade_permissions_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role OR NEW.name <> 'platform_owner' OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='platform'
    ) THEN
        RETURN NEW;
    END IF;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        VALUES (NEW.id,'control.upgrades.read'),(NEW.id,'control.upgrades.manage')
        ON CONFLICT DO NOTHING
        RETURNING role_id,permission_name
    )
    INSERT INTO control_upgrade_rbac_grant_additions_096(role_id,scope_id,permission_name)
    SELECT role_id,NEW.scope_id,permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_control_upgrade_permissions_096
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_control_upgrade_permissions_096();

CREATE FUNCTION protect_control_upgrade_rbac_provenance_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='INSERT' AND pg_trigger_depth() >= 2 THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'control upgrade RBAC provenance is immutable' USING ERRCODE='P9602';
END;
$$;

CREATE TRIGGER control_upgrade_rbac_provenance_row_096
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_rbac_grant_additions_096
FOR EACH ROW EXECUTE FUNCTION protect_control_upgrade_rbac_provenance_096();
CREATE TRIGGER control_upgrade_rbac_provenance_truncate_096
BEFORE TRUNCATE ON control_upgrade_rbac_grant_additions_096
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_upgrade_rbac_provenance_096();
ALTER TABLE control_upgrade_rbac_grant_additions_096
    ENABLE ALWAYS TRIGGER control_upgrade_rbac_provenance_row_096;
ALTER TABLE control_upgrade_rbac_grant_additions_096
    ENABLE ALWAYS TRIGGER control_upgrade_rbac_provenance_truncate_096;

ALTER TABLE control_upgrade_rollout_plans
    ADD COLUMN parent_grant_id uuid,
    ADD COLUMN parent_grant_bytes bytea,
    ADD COLUMN parent_grant_sha256 bytea,
    ADD COLUMN parent_grant_expires_at timestamptz,
    ADD COLUMN artifact_bundle_id uuid,
    ADD COLUMN artifact_bundle_bytes bytea,
    ADD COLUMN artifact_bundle_sha256 bytea,
    ADD COLUMN command_issuance_not_after timestamptz,
    ADD COLUMN forward_profile_bytes bytea,
    ADD COLUMN forward_profile_sha256 bytea,
    ADD COLUMN rollback_profile_bytes bytea,
    ADD COLUMN rollback_profile_sha256 bytea,
    ADD COLUMN artifact_size_bytes bigint,
    ADD COLUMN rollback_artifact_size_bytes bigint;

ALTER TABLE control_upgrade_node_commands
    ADD COLUMN command_grant_bytes bytea,
    ADD COLUMN command_grant_sha256 bytea,
    ADD COLUMN command_grant_expires_at timestamptz;

ALTER TABLE control_upgrade_outbox
    ADD COLUMN published_stream text,
    ADD COLUMN published_sequence bigint;

CREATE TABLE control_upgrade_grant_intents_096 (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    candidate_plan_id uuid NOT NULL UNIQUE,
    plan_id uuid,
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9._-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ '^[A-Za-z0-9._-]+$'
    ),
    state text NOT NULL CHECK (state IN ('reserved','acquired','consumed')),
    parent_grant_bytes bytea,
    parent_grant_sha256 bytea,
    parent_grant_expires_at timestamptz,
    artifact_bundle_id uuid,
    artifact_bundle_bytes bytea,
    artifact_bundle_sha256 bytea,
    command_issuance_not_after timestamptz,
    forward_profile_bytes bytea,
    forward_profile_sha256 bytea,
    rollback_profile_bytes bytea,
    rollback_profile_sha256 bytea,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id,actor_user_id,idempotency_key),
    UNIQUE (plan_id),
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES control_upgrade_rollout_plans(id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (
        (state='reserved' AND plan_id IS NULL AND parent_grant_bytes IS NULL AND
         parent_grant_sha256 IS NULL AND parent_grant_expires_at IS NULL AND
         artifact_bundle_id IS NULL AND artifact_bundle_bytes IS NULL AND
         artifact_bundle_sha256 IS NULL AND command_issuance_not_after IS NULL AND
         forward_profile_bytes IS NULL AND forward_profile_sha256 IS NULL AND
         rollback_profile_bytes IS NULL AND rollback_profile_sha256 IS NULL) OR
        (state IN ('acquired','consumed') AND
         octet_length(parent_grant_bytes)>0 AND octet_length(parent_grant_sha256)=32 AND
         sha256(parent_grant_bytes)=parent_grant_sha256 AND parent_grant_expires_at>created_at AND
         artifact_bundle_id IS NOT NULL AND octet_length(artifact_bundle_bytes)>0 AND
         octet_length(artifact_bundle_sha256)=32 AND sha256(artifact_bundle_bytes)=artifact_bundle_sha256 AND
         command_issuance_not_after>created_at AND
         octet_length(forward_profile_bytes)>0 AND octet_length(forward_profile_sha256)=32 AND
         sha256(forward_profile_bytes)=forward_profile_sha256 AND
         octet_length(rollback_profile_bytes)>0 AND octet_length(rollback_profile_sha256)=32 AND
         sha256(rollback_profile_bytes)=rollback_profile_sha256 AND
         ((state='consumed' AND plan_id=candidate_plan_id) OR
          (state='acquired' AND plan_id IS NULL)))
    )
);

CREATE TABLE control_upgrade_write_receipts_096 (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('create','start','pause','resume','rollback')),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ '^[A-Za-z0-9._-]+$'
    ),
    result_snapshot_bytes bytea NOT NULL CHECK (octet_length(result_snapshot_bytes)>0),
    result_snapshot_sha256 bytea NOT NULL CHECK (octet_length(result_snapshot_sha256)=32),
    result_revision bigint NOT NULL CHECK (result_revision>0),
    audit_event_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id,actor_user_id,idempotency_key),
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES control_upgrade_rollout_plans(id) ON DELETE RESTRICT,
    FOREIGN KEY (audit_event_id) REFERENCES audit_events(id) ON DELETE RESTRICT,
    CHECK (sha256(result_snapshot_bytes)=result_snapshot_sha256),
    CHECK (completed_at>=created_at)
);

CREATE TABLE control_upgrade_outbox_rejections_096 (
    command_id uuid PRIMARY KEY,
    outbox_id uuid NOT NULL UNIQUE,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision>0),
    installation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    stream text NOT NULL CHECK (stream<>''),
    subject text NOT NULL CHECK (subject<>''),
    message_id text NOT NULL CHECK (message_id<>''),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
    error_code text NOT NULL CHECK (error_code ~ '^[a-z][a-z0-9_]{0,95}$'),
    rejected_at timestamptz NOT NULL,
    FOREIGN KEY (outbox_id) REFERENCES control_upgrade_outbox(id) ON DELETE RESTRICT,
    FOREIGN KEY (command_id) REFERENCES control_upgrade_node_commands(command_id) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id,plan_revision)
        REFERENCES control_upgrade_rollout_events(plan_id,revision) ON DELETE RESTRICT
);

CREATE TABLE control_upgrade_status_rejections_096 (
    id uuid PRIMARY KEY,
    stream text NOT NULL CHECK (stream='AGENT_DEPLOYMENT_STATUS'),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
    header_sha256 bytea NOT NULL CHECK (octet_length(header_sha256)=32),
    reason text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{0,95}$'),
    rejected_at timestamptz NOT NULL,
    UNIQUE (stream,subject,payload_sha256,header_sha256,reason)
);

CREATE UNIQUE INDEX control_upgrade_denied_audit_096
ON audit_events(scope_id,actor_user_id,action,request_id)
WHERE result='denied' AND action IN (
    'control_upgrade_rollout.create','control_upgrade_rollout.start',
    'control_upgrade_rollout.pause','control_upgrade_rollout.resume',
    'control_upgrade_rollout.rollback'
);

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

CREATE FUNCTION validate_control_upgrade_command_grant_096()
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

CREATE TRIGGER control_upgrade_command_grant_validate_096
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_node_commands
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_command_grant_096();

CREATE FUNCTION validate_control_upgrade_outbox_ack_096()
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

CREATE TRIGGER control_upgrade_outbox_ack_validate_096
BEFORE INSERT OR UPDATE ON control_upgrade_outbox
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_outbox_ack_096();

CREATE FUNCTION validate_control_upgrade_grant_intent_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'control upgrade grant intents are durable facts' USING ERRCODE='P9602';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'reserved' OR NEW.plan_id IS NOT NULL OR NEW.updated_at<>NEW.created_at THEN
            RAISE EXCEPTION 'invalid initial control upgrade grant intent' USING ERRCODE='P9602';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.actor_scope_id,NEW.actor_user_id,NEW.installation_id,
       NEW.candidate_plan_id,NEW.idempotency_key,NEW.request_digest,NEW.request_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.actor_scope_id,OLD.actor_user_id,OLD.installation_id,
       OLD.candidate_plan_id,OLD.idempotency_key,OLD.request_digest,OLD.request_id,OLD.created_at) OR
       NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'control upgrade grant intent identity is immutable' USING ERRCODE='P9602';
    END IF;
    IF OLD.state='reserved' THEN
        IF ROW(OLD.parent_grant_bytes,OLD.parent_grant_sha256,OLD.parent_grant_expires_at,
               OLD.artifact_bundle_id,OLD.artifact_bundle_bytes,OLD.artifact_bundle_sha256,
               OLD.command_issuance_not_after,OLD.forward_profile_bytes,OLD.forward_profile_sha256,
               OLD.rollback_profile_bytes,OLD.rollback_profile_sha256)
           IS DISTINCT FROM ROW(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL) THEN
            RAISE EXCEPTION 'reserved control upgrade grant intent binding is immutable'
                USING ERRCODE='P9602';
        END IF;
        IF NEW.state<>'acquired' OR NEW.plan_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid control upgrade grant intent transition' USING ERRCODE='P9602';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='acquired' THEN
        IF NEW.state<>'consumed' OR NEW.plan_id IS DISTINCT FROM OLD.candidate_plan_id OR
           ROW(NEW.parent_grant_bytes,NEW.parent_grant_sha256,NEW.parent_grant_expires_at,
               NEW.artifact_bundle_id,NEW.artifact_bundle_bytes,NEW.artifact_bundle_sha256,
               NEW.command_issuance_not_after,NEW.forward_profile_bytes,NEW.forward_profile_sha256,
               NEW.rollback_profile_bytes,NEW.rollback_profile_sha256)
           IS DISTINCT FROM ROW(OLD.parent_grant_bytes,OLD.parent_grant_sha256,OLD.parent_grant_expires_at,
               OLD.artifact_bundle_id,OLD.artifact_bundle_bytes,OLD.artifact_bundle_sha256,
               OLD.command_issuance_not_after,OLD.forward_profile_bytes,OLD.forward_profile_sha256,
               OLD.rollback_profile_bytes,OLD.rollback_profile_sha256) THEN
            RAISE EXCEPTION 'acquired control upgrade grant intent binding is immutable'
                USING ERRCODE='P9602';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'control upgrade grant intent is terminal' USING ERRCODE='P9602';
END;
$$;

CREATE TRIGGER control_upgrade_grant_intent_validate_096
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_grant_intents_096
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_grant_intent_096();

CREATE FUNCTION validate_control_upgrade_consumed_intent_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state='consumed' AND NOT EXISTS (
        SELECT 1 FROM control_upgrade_write_receipts_096 receipt
        WHERE receipt.operation='create' AND receipt.actor_scope_id=NEW.actor_scope_id
          AND receipt.actor_user_id=NEW.actor_user_id
          AND receipt.installation_id=NEW.installation_id
          AND receipt.plan_id=NEW.candidate_plan_id
          AND receipt.idempotency_key=NEW.idempotency_key
          AND receipt.request_digest=NEW.request_digest
          AND receipt.request_id=NEW.request_id
    ) THEN
        RAISE EXCEPTION 'control upgrade consumed grant intent requires exact create receipt'
            USING ERRCODE='P9602';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER control_upgrade_grant_intent_consumed_096
AFTER INSERT OR UPDATE ON control_upgrade_grant_intents_096
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_consumed_intent_096();

CREATE FUNCTION validate_control_upgrade_runtime_fact_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'control upgrade runtime facts are append-only' USING ERRCODE='P9602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_grant_intent_no_truncate_096
BEFORE TRUNCATE ON control_upgrade_grant_intents_096
FOR EACH STATEMENT EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_write_receipt_append_only_096
BEFORE UPDATE OR DELETE ON control_upgrade_write_receipts_096
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_rejection_append_only_096
BEFORE UPDATE OR DELETE ON control_upgrade_outbox_rejections_096
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_status_rejection_append_only_096
BEFORE UPDATE OR DELETE ON control_upgrade_status_rejections_096
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_write_receipt_no_truncate_096
BEFORE TRUNCATE ON control_upgrade_write_receipts_096
FOR EACH STATEMENT EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_rejection_no_truncate_096
BEFORE TRUNCATE ON control_upgrade_outbox_rejections_096
FOR EACH STATEMENT EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();
CREATE TRIGGER control_upgrade_status_rejection_no_truncate_096
BEFORE TRUNCATE ON control_upgrade_status_rejections_096
FOR EACH STATEMENT EXECUTE FUNCTION validate_control_upgrade_runtime_fact_096();

CREATE FUNCTION validate_control_upgrade_write_receipt_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    audit_row audit_events%ROWTYPE;
    plan_row control_upgrade_rollout_plans%ROWTYPE;
BEGIN
    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id FOR SHARE;
    SELECT * INTO plan_row FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF audit_row.id IS NULL OR plan_row.id IS NULL OR
       audit_row.scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'control_upgrade_rollout.'||NEW.operation OR
       audit_row.resource_type IS DISTINCT FROM 'control_upgrade_rollout' OR
       audit_row.resource_id IS DISTINCT FROM NEW.plan_id::text OR
       audit_row.request_id IS DISTINCT FROM NEW.request_id OR audit_row.result<>'success' OR
       plan_row.installation_id<>NEW.installation_id OR plan_row.revision<>NEW.result_revision OR
       plan_row.canonical_snapshot_bytes<>NEW.result_snapshot_bytes OR
       plan_row.canonical_snapshot_sha256<>NEW.result_snapshot_sha256 OR
       audit_row.occurred_at>NEW.completed_at THEN
        RAISE EXCEPTION 'invalid control upgrade write receipt binding' USING ERRCODE='P9602';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER control_upgrade_write_receipt_audit_096
AFTER INSERT ON control_upgrade_write_receipts_096
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_write_receipt_096();

CREATE FUNCTION validate_control_upgrade_status_semantics_096()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command control_upgrade_node_commands%ROWTYPE;
    plan_snapshot_bytes bytea;
    plan_snapshot jsonb;
    previous_revision bigint;
    previous_state text;
    previous_observed_at timestamptz;
    previous_status_bytes bytea;
    previous_status_document jsonb;
    previous_installer_transaction_id text;
    has_previous boolean;
    rolling_back_status_bytes bytea;
    rolling_back_status_document jsonb;
    rollback_trigger_error text;
    command_payload_sha bytea;
    outbox_state text;
    status_document jsonb;
    status_field_count bigint;
    installer_transaction_id text;
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'upgrade status receipts are immutable facts' USING ERRCODE='P9302';
    END IF;
    IF NEW.status_revision<1 OR octet_length(NEW.status_bytes)=0 OR
       octet_length(NEW.status_sha256)<>32 OR sha256(NEW.status_bytes)<>NEW.status_sha256 OR
       octet_length(NEW.command_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid upgrade status tuple' USING ERRCODE='P9302';
    END IF;
    SELECT * INTO command FROM control_upgrade_node_commands WHERE command_id=NEW.command_id FOR UPDATE;
    IF NOT FOUND OR ROW(NEW.plan_id,NEW.plan_revision,NEW.batch_id,NEW.actor_scope_id,NEW.actor_user_id,
       NEW.installation_id,NEW.node_id,NEW.action) IS DISTINCT FROM ROW(command.plan_id,command.plan_revision,
       command.batch_id,command.actor_scope_id,command.actor_user_id,command.installation_id,command.node_id,
       command.action) OR command.state NOT IN ('published','acknowledged') OR command.published_at IS NULL OR
       NEW.observed_at<command.published_at OR
       NEW.observed_at>transaction_timestamp()+interval '30 seconds' THEN
        RAISE EXCEPTION 'invalid upgrade status binding' USING ERRCODE='P9302';
    END IF;
    SELECT payload_sha256,state INTO command_payload_sha,outbox_state
    FROM control_upgrade_outbox WHERE command_id=NEW.command_id FOR UPDATE;
    IF NOT FOUND OR outbox_state<>'published' OR NEW.command_sha256<>command_payload_sha THEN
        RAISE EXCEPTION 'invalid upgrade status command digest' USING ERRCODE='P9302';
    END IF;
    SELECT canonical_snapshot_bytes INTO plan_snapshot_bytes
    FROM control_upgrade_rollout_plans WHERE id=NEW.plan_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid upgrade status plan binding' USING ERRCODE='P9302';
    END IF;
    BEGIN
        plan_snapshot := convert_from(plan_snapshot_bytes,'UTF8')::jsonb;
        status_document := convert_from(NEW.status_bytes,'UTF8')::jsonb;
        SELECT count(*) INTO status_field_count FROM jsonb_object_keys(status_document);
        installer_transaction_id := status_document->>'installer_transaction_id';
        IF jsonb_typeof(status_document)<>'object' OR status_field_count<>16 OR NOT
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
           (installer_transaction_id<>'' AND installer_transaction_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
           (status_document->>'error_code'<>'' AND
            status_document->>'error_code' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') THEN
            RAISE EXCEPTION 'invalid upgrade status document' USING ERRCODE='P9302';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9302' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid upgrade status json' USING ERRCODE='P9302';
    END;
    IF NEW.state NOT IN ('accepted','claimed','installing','healthy','failed','rolling_back','rolled_back','uncertain') THEN
        RAISE EXCEPTION 'invalid upgrade status state' USING ERRCODE='P9302';
    END IF;
    SELECT status_revision,state,observed_at,status_bytes
    INTO previous_revision,previous_state,previous_observed_at,previous_status_bytes
    FROM control_upgrade_status_receipts WHERE command_id=NEW.command_id
    ORDER BY status_revision DESC LIMIT 1;
    has_previous := FOUND;

    IF previous_state IN ('installing','rolling_back','uncertain') THEN
        BEGIN
            previous_status_document := convert_from(previous_status_bytes,'UTF8')::jsonb;
            previous_installer_transaction_id :=
                previous_status_document->>'installer_transaction_id';
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid previous upgrade status json' USING ERRCODE='P9302';
        END;
        IF previous_installer_transaction_id='' OR
           installer_transaction_id IS DISTINCT FROM previous_installer_transaction_id THEN
            RAISE EXCEPTION 'invalid upgrade status transaction continuity' USING ERRCODE='P9302';
        END IF;
    END IF;

    IF command.action='upgrade' AND NEW.state='rolled_back' THEN
        SELECT status_bytes INTO rolling_back_status_bytes
        FROM control_upgrade_status_receipts
        WHERE command_id=NEW.command_id AND state='rolling_back' AND
              status_revision<NEW.status_revision
        ORDER BY status_revision DESC LIMIT 1;
        IF FOUND THEN
            BEGIN
                rolling_back_status_document :=
                    convert_from(rolling_back_status_bytes,'UTF8')::jsonb;
                rollback_trigger_error := rolling_back_status_document->>'error_code';
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION 'invalid rolling back status json' USING ERRCODE='P9302';
            END;
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
           installer_transaction_id='' OR
           status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command.action='upgrade' AND NEW.state='rolling_back' AND (
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'='' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (NEW.state='healthy' AND (
           command.action<>'upgrade' OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command.action='upgrade' AND NEW.state='rolled_back' AND (
           previous_state NOT IN ('rolling_back','uncertain') OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'='' OR
           (rollback_trigger_error IS NOT NULL AND
            status_document->>'error_code' IS DISTINCT FROM rollback_trigger_error) OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (command.action='rollback' AND NEW.state='rolled_back' AND (
           previous_state NOT IN ('installing','uncertain') OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion' OR
           status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           installer_transaction_id='' OR status_document->>'error_code'<>'' OR
           status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb)) OR
       (NEW.state='failed' AND (
           command.action NOT IN ('upgrade','rollback') OR
           status_document->>'error_code'='ROLLBACK_FAILED' OR
           installer_transaction_id='' OR status_document->>'error_code'='' OR
           status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR
           (command.action='upgrade' AND status_document->>'previous_version'<>'') OR
           (command.action='rollback' AND
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
    IF NOT has_previous THEN
        IF NEW.status_revision<>1 OR NEW.state NOT IN ('accepted','claimed') THEN
            RAISE EXCEPTION 'invalid initial upgrade status' USING ERRCODE='P9302';
        END IF;
    ELSIF NEW.status_revision<>previous_revision+1 OR NEW.observed_at<previous_observed_at OR NOT (
       (previous_state='accepted' AND NEW.state='claimed') OR
       (previous_state='claimed' AND NEW.state='installing') OR
       (previous_state='installing' AND command.action='upgrade' AND
        NEW.state IN ('healthy','failed','rolling_back','uncertain')) OR
       (previous_state='installing' AND command.action='rollback' AND
        NEW.state IN ('failed','rolled_back','uncertain')) OR
       (previous_state='rolling_back' AND command.action='upgrade' AND NEW.state IN ('rolled_back','uncertain')) OR
       (previous_state='uncertain' AND command.action='upgrade' AND
        NEW.state IN ('uncertain','healthy','failed','rolled_back')) OR
       (previous_state='uncertain' AND command.action='rollback' AND
        NEW.state IN ('uncertain','failed','rolled_back'))
    ) THEN
        RAISE EXCEPTION 'invalid upgrade status transition' USING ERRCODE='P9302';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_status_semantics_096
BEFORE INSERT ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_semantics_096();

REVOKE ALL ON TABLE control_upgrade_rbac_grant_additions_096 FROM PUBLIC;
REVOKE ALL ON TABLE control_upgrade_grant_intents_096 FROM PUBLIC;
REVOKE ALL ON TABLE control_upgrade_write_receipts_096 FROM PUBLIC;
REVOKE ALL ON TABLE control_upgrade_outbox_rejections_096 FROM PUBLIC;
REVOKE ALL ON TABLE control_upgrade_status_rejections_096 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_control_upgrade_permissions_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION project_control_upgrade_permissions_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_control_upgrade_rbac_provenance_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_command_grant_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_outbox_ack_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_grant_intent_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_consumed_intent_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_runtime_fact_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_write_receipt_096() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_status_semantics_096() FROM PUBLIC;
