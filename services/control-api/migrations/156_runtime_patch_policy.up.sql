LOCK TABLE schema_migrations,control_installation_entitlement IN ACCESS EXCLUSIVE MODE;

DO $migration_156$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>155 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>155 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=155 AND migration_id='155_dns_provider_retry_states' AND
              checksum_sha256='d19d14aee41a7b17ba69cb02e4d0a6d256496b1d84ce8a9f7eb376796de51e48' AND
              down_checksum_sha256='db2bd655adda8eab882f08957fa5fa1a31233c87f36ab0555eff48bd46fc661b' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=154 AND migration_id='154_control_upgrade_systemd_repository' AND
              checksum_sha256='b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a' AND
              down_checksum_sha256='85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('runtime_patch_policy_candidates_156') IS NOT NULL OR
         to_regclass('runtime_patch_policy_receipts_156') IS NOT NULL OR
         to_regclass('runtime_patch_policy_heads_156') IS NOT NULL OR
         to_regprocedure('commit_runtime_patch_policy_156(text,text,text,text,bigint,boolean,bigint,bytea,bytea,bytea,bigint,text,text,bigint,text,bytea,bytea,bigint,bytea,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bytea)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 156 requires a contiguous verified 155 release head'
            USING ERRCODE='P1560';
    END IF;
END;
$migration_156$;

CREATE TABLE runtime_patch_policy_candidates_156 (
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    target_kind text NOT NULL CHECK(target_kind IN ('control','agent')),
    target_id text NOT NULL CHECK(target_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    channel text NOT NULL CHECK(channel IN ('stable','beta','lts','security-hotfix')),
    revision bigint NOT NULL CHECK(revision>0),
    candidate_sha256 bytea NOT NULL CHECK(octet_length(candidate_sha256)=32),
    candidate_wire bytea NOT NULL CHECK(octet_length(candidate_wire) BETWEEN 1 AND 4194304),
    candidate_wire_sha256 bytea NOT NULL CHECK(octet_length(candidate_wire_sha256)=32),
    candidate_size bigint NOT NULL CHECK(candidate_size BETWEEN 1 AND 4194304),
    key_id text NOT NULL CHECK(key_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    key_lineage text NOT NULL CHECK(key_lineage ~ '^[a-z][a-z0-9._-]{0,127}$'),
    key_revision bigint NOT NULL CHECK(key_revision>0),
    action text NOT NULL CHECK(action IN ('canary','pause','expand','withdraw','rollback')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(created_at)),
    PRIMARY KEY(installation_id,target_kind,target_id,channel,revision),
    UNIQUE(installation_id,target_kind,target_id,channel,revision,candidate_sha256),
    CHECK(candidate_wire_sha256=sha256(candidate_wire)),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,installation_id}')=installation_id),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,target_kind}')=target_kind),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,target_id}')=target_id),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,channel}')=channel),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,revision}')::bigint=revision),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{candidate,action}')=action),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{envelope,key_id}')=key_id),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{envelope,key_lineage}')=key_lineage),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{envelope,key_revision}')::bigint=key_revision),
    CHECK((convert_from(candidate_wire,'UTF8')::jsonb#>>'{envelope,candidate_size}')::bigint=candidate_size)
);

CREATE TABLE runtime_patch_policy_receipts_156 (
    installation_id text NOT NULL,
    target_kind text NOT NULL,
    target_id text NOT NULL,
    channel text NOT NULL,
    receipt_id uuid NOT NULL,
    receipt_kind text NOT NULL CHECK(receipt_kind IN ('decision','rollback_approval','activation')),
    candidate_revision bigint NOT NULL CHECK(candidate_revision>0),
    candidate_sha256 bytea NOT NULL CHECK(octet_length(candidate_sha256)=32),
    key_id text NOT NULL CHECK(key_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    key_lineage text NOT NULL CHECK(key_lineage ~ '^[a-z][a-z0-9._-]{0,127}$'),
    key_revision bigint NOT NULL CHECK(key_revision>0),
    status text NOT NULL CHECK(status ~ '^[a-z][a-z0-9_]{0,63}$'),
    receipt_bytes bytea NOT NULL CHECK(octet_length(receipt_bytes) BETWEEN 1 AND 65536),
    receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
    observed_at timestamptz NOT NULL CHECK(isfinite(observed_at) AND date_trunc('microseconds',observed_at)=observed_at),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(created_at)),
    PRIMARY KEY(installation_id,target_kind,target_id,channel,receipt_id),
    FOREIGN KEY(installation_id,target_kind,target_id,channel,candidate_revision,candidate_sha256)
        REFERENCES runtime_patch_policy_candidates_156(
            installation_id,target_kind,target_id,channel,revision,candidate_sha256) ON DELETE RESTRICT,
    CHECK(receipt_sha256=sha256(receipt_bytes)),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'schema')='cdnca.runtime-patch-policy-receipt/v1'),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'id')::uuid=receipt_id),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'kind')=receipt_kind),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'installation_id')=installation_id),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'target_kind')=target_kind),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'target_id')=target_id),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'channel')=channel),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'candidate_revision')::bigint=candidate_revision),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'key_id')=key_id),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'key_lineage')=key_lineage),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'key_revision')::bigint=key_revision),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'status')=status),
    CHECK((convert_from(receipt_bytes,'UTF8')::jsonb->>'observed_at')::timestamptz=observed_at)
);

CREATE TABLE runtime_patch_policy_heads_156 (
    installation_id text NOT NULL,
    target_kind text NOT NULL,
    target_id text NOT NULL,
    channel text NOT NULL,
    resource_version bigint NOT NULL CHECK(resource_version>0),
    head_revision bigint NOT NULL,
    head_candidate_sha256 bytea NOT NULL CHECK(octet_length(head_candidate_sha256)=32),
    approved_lkg_revision bigint,
    approved_lkg_candidate_sha256 bytea,
    rollback_approval_receipt_id uuid,
    snapshot_bytes bytea NOT NULL CHECK(octet_length(snapshot_bytes) BETWEEN 1 AND 10485760),
    snapshot_sha256 bytea NOT NULL CHECK(octet_length(snapshot_sha256)=32),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(updated_at)),
    PRIMARY KEY(installation_id,target_kind,target_id,channel),
    FOREIGN KEY(installation_id,target_kind,target_id,channel,head_revision,head_candidate_sha256)
        REFERENCES runtime_patch_policy_candidates_156(
            installation_id,target_kind,target_id,channel,revision,candidate_sha256) ON DELETE RESTRICT,
    FOREIGN KEY(installation_id,target_kind,target_id,channel,approved_lkg_revision,approved_lkg_candidate_sha256)
        REFERENCES runtime_patch_policy_candidates_156(
            installation_id,target_kind,target_id,channel,revision,candidate_sha256) ON DELETE RESTRICT,
    FOREIGN KEY(installation_id,target_kind,target_id,channel,rollback_approval_receipt_id)
        REFERENCES runtime_patch_policy_receipts_156(
            installation_id,target_kind,target_id,channel,receipt_id) ON DELETE RESTRICT,
    CHECK((approved_lkg_revision IS NULL)=(approved_lkg_candidate_sha256 IS NULL)),
    CHECK(approved_lkg_candidate_sha256 IS NULL OR octet_length(approved_lkg_candidate_sha256)=32),
    CHECK(snapshot_sha256=sha256(snapshot_bytes))
);

CREATE FUNCTION guard_runtime_patch_policy_candidate_156()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime patch policy candidates are immutable'
        USING ERRCODE='P1561';
END;
$$;

CREATE FUNCTION guard_runtime_patch_policy_receipt_156()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime patch policy receipts are immutable'
        USING ERRCODE='P1561';
END;
$$;

CREATE FUNCTION guard_runtime_patch_policy_head_156()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'runtime patch policy heads cannot be deleted'
            USING ERRCODE='P1561';
    END IF;
    IF TG_OP='INSERT' AND (NEW.resource_version<>1 OR NEW.head_revision<>1) THEN
        RAISE EXCEPTION 'runtime patch policy head must begin at revision one'
            USING ERRCODE='P1561';
    END IF;
    IF TG_OP='UPDATE' AND (
        NEW.resource_version<>OLD.resource_version+1 OR NEW.head_revision<>OLD.head_revision+1 OR
        NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
        NEW.target_kind IS DISTINCT FROM OLD.target_kind OR NEW.target_id IS DISTINCT FROM OLD.target_id OR
        NEW.channel IS DISTINCT FROM OLD.channel
    ) THEN
        RAISE EXCEPTION 'runtime patch policy head CAS or identity is invalid'
            USING ERRCODE='P1561';
    END IF;
    NEW.updated_at:=transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_runtime_patch_policy_truncate_156()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime patch policy facts cannot be truncated'
        USING ERRCODE='P1561';
END;
$$;

CREATE TRIGGER runtime_patch_policy_candidate_guard_156
BEFORE UPDATE OR DELETE ON runtime_patch_policy_candidates_156
FOR EACH ROW EXECUTE FUNCTION guard_runtime_patch_policy_candidate_156();

CREATE TRIGGER runtime_patch_policy_receipt_guard_156
BEFORE UPDATE OR DELETE ON runtime_patch_policy_receipts_156
FOR EACH ROW EXECUTE FUNCTION guard_runtime_patch_policy_receipt_156();

CREATE TRIGGER runtime_patch_policy_head_guard_156
BEFORE INSERT OR UPDATE OR DELETE ON runtime_patch_policy_heads_156
FOR EACH ROW EXECUTE FUNCTION guard_runtime_patch_policy_head_156();

CREATE TRIGGER runtime_patch_policy_candidate_truncate_156
BEFORE TRUNCATE ON runtime_patch_policy_candidates_156
FOR EACH STATEMENT EXECUTE FUNCTION prevent_runtime_patch_policy_truncate_156();

CREATE TRIGGER runtime_patch_policy_receipt_truncate_156
BEFORE TRUNCATE ON runtime_patch_policy_receipts_156
FOR EACH STATEMENT EXECUTE FUNCTION prevent_runtime_patch_policy_truncate_156();

CREATE TRIGGER runtime_patch_policy_head_truncate_156
BEFORE TRUNCATE ON runtime_patch_policy_heads_156
FOR EACH STATEMENT EXECUTE FUNCTION prevent_runtime_patch_policy_truncate_156();

CREATE FUNCTION append_runtime_patch_policy_receipt_156(
    p_installation_id text,p_target_kind text,p_target_id text,p_channel text,
    p_expected_kind text,p_receipt_bytes bytea,p_receipt_sha256 bytea
) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
    receipt jsonb;
    parsed_receipt_id uuid;
    candidate_digest bytea;
BEGIN
    IF p_receipt_bytes IS NULL THEN
        RETURN NULL;
    END IF;
    IF p_receipt_sha256 IS NULL OR p_receipt_sha256<>sha256(p_receipt_bytes) THEN
        RAISE EXCEPTION 'runtime patch policy receipt digest mismatch' USING ERRCODE='P1561';
    END IF;
    receipt:=convert_from(p_receipt_bytes,'UTF8')::jsonb;
    parsed_receipt_id:=(receipt->>'id')::uuid;
    IF receipt->>'kind'<>p_expected_kind THEN
        RAISE EXCEPTION 'runtime patch policy receipt kind mismatch' USING ERRCODE='P1561';
    END IF;
    candidate_digest:=decode(translate(receipt->>'candidate_sha256','-_','+/')||'=','base64');
    INSERT INTO runtime_patch_policy_receipts_156(
        installation_id,target_kind,target_id,channel,receipt_id,receipt_kind,candidate_revision,
        candidate_sha256,key_id,key_lineage,key_revision,status,receipt_bytes,receipt_sha256,observed_at)
    VALUES(p_installation_id,p_target_kind,p_target_id,p_channel,parsed_receipt_id,p_expected_kind,
        (receipt->>'candidate_revision')::bigint,candidate_digest,receipt->>'key_id',receipt->>'key_lineage',
        (receipt->>'key_revision')::bigint,receipt->>'status',p_receipt_bytes,p_receipt_sha256,
        (receipt->>'observed_at')::timestamptz)
    ON CONFLICT DO NOTHING;
    IF NOT EXISTS (
        SELECT 1 FROM runtime_patch_policy_receipts_156
        WHERE installation_id=p_installation_id AND target_kind=p_target_kind AND target_id=p_target_id AND
              channel=p_channel AND receipt_id=parsed_receipt_id AND
              receipt_kind=p_expected_kind AND receipt_bytes=p_receipt_bytes AND receipt_sha256=p_receipt_sha256
    ) THEN
        RAISE EXCEPTION 'runtime patch policy receipt idempotency conflict' USING ERRCODE='P1561';
    END IF;
    RETURN parsed_receipt_id;
END;
$$;

CREATE FUNCTION commit_runtime_patch_policy_156(
    p_installation_id text,p_target_kind text,p_target_id text,p_channel text,
    p_expected_resource_version bigint,p_advance boolean,p_candidate_revision bigint,p_candidate_sha256 bytea,
    p_candidate_wire bytea,p_candidate_wire_sha256 bytea,p_candidate_size bigint,p_key_id text,
    p_key_lineage text,p_key_revision bigint,p_action text,p_snapshot_bytes bytea,p_snapshot_sha256 bytea,
    p_head_revision bigint,p_head_candidate_sha256 bytea,p_lkg_revision bigint,p_lkg_candidate_sha256 bytea,
    p_decision_receipt bytea,p_decision_receipt_sha256 bytea,p_approval_receipt bytea,
    p_approval_receipt_sha256 bytea,p_activation_receipt bytea,p_activation_receipt_sha256 bytea
) RETURNS TABLE(resource_version bigint,snapshot_bytes bytea,snapshot_sha256 bytea)
LANGUAGE plpgsql AS $$
DECLARE
    current_version bigint;
    approval_receipt_id uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        p_installation_id||'/'||p_target_kind||'/'||p_target_id||'/'||p_channel,156));
    SELECT head.resource_version INTO current_version
    FROM runtime_patch_policy_heads_156 head
    WHERE head.installation_id=p_installation_id AND head.target_kind=p_target_kind AND
          head.target_id=p_target_id AND head.channel=p_channel
    FOR UPDATE;
    current_version:=COALESCE(current_version,0);
    IF current_version<>p_expected_resource_version OR p_expected_resource_version<0 OR
       p_snapshot_sha256<>sha256(p_snapshot_bytes) OR p_candidate_wire_sha256<>sha256(p_candidate_wire) THEN
        RAISE EXCEPTION 'runtime patch policy CAS or digest conflict' USING ERRCODE='P1561';
    END IF;

    INSERT INTO runtime_patch_policy_candidates_156(
        installation_id,target_kind,target_id,channel,revision,candidate_sha256,candidate_wire,
        candidate_wire_sha256,candidate_size,key_id,key_lineage,key_revision,action)
    VALUES(p_installation_id,p_target_kind,p_target_id,p_channel,p_candidate_revision,p_candidate_sha256,
        p_candidate_wire,p_candidate_wire_sha256,p_candidate_size,p_key_id,p_key_lineage,p_key_revision,p_action)
    ON CONFLICT DO NOTHING;
    IF NOT EXISTS (
        SELECT 1 FROM runtime_patch_policy_candidates_156 candidate
        WHERE candidate.installation_id=p_installation_id AND candidate.target_kind=p_target_kind AND
              candidate.target_id=p_target_id AND candidate.channel=p_channel AND
              candidate.revision=p_candidate_revision AND candidate.candidate_sha256=p_candidate_sha256 AND
              candidate.candidate_wire=p_candidate_wire AND candidate.candidate_wire_sha256=p_candidate_wire_sha256 AND
              candidate.candidate_size=p_candidate_size AND candidate.key_id=p_key_id AND
              candidate.key_lineage=p_key_lineage AND candidate.key_revision=p_key_revision AND candidate.action=p_action
    ) THEN
        RAISE EXCEPTION 'runtime patch policy candidate idempotency conflict' USING ERRCODE='P1561';
    END IF;

    PERFORM append_runtime_patch_policy_receipt_156(p_installation_id,p_target_kind,p_target_id,p_channel,
        'decision',p_decision_receipt,p_decision_receipt_sha256);
    approval_receipt_id:=append_runtime_patch_policy_receipt_156(p_installation_id,p_target_kind,p_target_id,p_channel,
        'rollback_approval',p_approval_receipt,p_approval_receipt_sha256);
    PERFORM append_runtime_patch_policy_receipt_156(p_installation_id,p_target_kind,p_target_id,p_channel,
        'activation',p_activation_receipt,p_activation_receipt_sha256);

    IF p_advance THEN
        IF p_head_revision IS NULL OR p_head_candidate_sha256 IS NULL OR
           p_head_revision<>p_candidate_revision OR p_head_candidate_sha256<>p_candidate_sha256 THEN
            RAISE EXCEPTION 'runtime patch policy head does not bind candidate' USING ERRCODE='P1561';
        END IF;
        IF current_version=0 THEN
            INSERT INTO runtime_patch_policy_heads_156(
                installation_id,target_kind,target_id,channel,resource_version,head_revision,head_candidate_sha256,
                approved_lkg_revision,approved_lkg_candidate_sha256,rollback_approval_receipt_id,
                snapshot_bytes,snapshot_sha256)
            VALUES(p_installation_id,p_target_kind,p_target_id,p_channel,1,p_head_revision,p_head_candidate_sha256,
                p_lkg_revision,p_lkg_candidate_sha256,approval_receipt_id,p_snapshot_bytes,p_snapshot_sha256);
        ELSE
            UPDATE runtime_patch_policy_heads_156 SET
                resource_version=current_version+1,head_revision=p_head_revision,
                head_candidate_sha256=p_head_candidate_sha256,approved_lkg_revision=p_lkg_revision,
                approved_lkg_candidate_sha256=p_lkg_candidate_sha256,
                rollback_approval_receipt_id=approval_receipt_id,snapshot_bytes=p_snapshot_bytes,
                snapshot_sha256=p_snapshot_sha256
            WHERE installation_id=p_installation_id AND target_kind=p_target_kind AND
                  target_id=p_target_id AND channel=p_channel AND resource_version=current_version;
        END IF;
        current_version:=current_version+1;
    ELSIF current_version>0 AND NOT EXISTS (
        SELECT 1 FROM runtime_patch_policy_heads_156 head
        WHERE head.installation_id=p_installation_id AND head.target_kind=p_target_kind AND
              head.target_id=p_target_id AND head.channel=p_channel AND
              head.snapshot_bytes=p_snapshot_bytes AND head.snapshot_sha256=p_snapshot_sha256
    ) THEN
        RAISE EXCEPTION 'runtime patch policy replay state conflict' USING ERRCODE='P1561';
    END IF;

    RETURN QUERY SELECT current_version,p_snapshot_bytes,p_snapshot_sha256;
END;
$$;

REVOKE ALL ON runtime_patch_policy_candidates_156 FROM PUBLIC;
REVOKE ALL ON runtime_patch_policy_receipts_156 FROM PUBLIC;
REVOKE ALL ON runtime_patch_policy_heads_156 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_runtime_patch_policy_candidate_156() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_runtime_patch_policy_receipt_156() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_runtime_patch_policy_head_156() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_runtime_patch_policy_truncate_156() FROM PUBLIC;
REVOKE ALL ON FUNCTION append_runtime_patch_policy_receipt_156(text,text,text,text,text,bytea,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION commit_runtime_patch_policy_156(text,text,text,text,bigint,boolean,bigint,bytea,bytea,bytea,bigint,text,text,bigint,text,bytea,bytea,bigint,bytea,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
