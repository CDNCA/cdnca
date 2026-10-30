LOCK TABLE schema_migrations,identity_verification_cases,identity_verification_evidence_reservations,
    auth_sessions,audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_169$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>168 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>168 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=168 AND migration_id='168_recharge_payment_cancellation' AND
              checksum_sha256='afbcb3861d04a9d76933ca497789000dbcfec30cf5bfa2a3f1640775b303ecba' AND
              down_checksum_sha256='ff328c94456cbbc35006a08c10e671a0196a628e40a4bdc0ec8232703d41dac0' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('identity_verification_provider_sessions_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 169 requires the exact verified 168 release head' USING ERRCODE='P1690';
    END IF;
END;
$migration_169$;

CREATE TABLE identity_verification_provider_sessions_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('personal_initial','personal_reverification','enterprise')),
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_session_id text CHECK(external_session_id IS NULL OR external_session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    evidence_token_digest bytea NOT NULL CHECK(octet_length(evidence_token_digest)=32),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    state text NOT NULL CHECK(state IN ('creating','pending','processing','succeeded','failed','canceled','expired','unknown')),
    failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    revision bigint NOT NULL CHECK(revision>0),
    attempt_count bigint NOT NULL CHECK(attempt_count>=0),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
    terminal_at timestamptz CHECK(terminal_at IS NULL OR isfinite(terminal_at)),
    retention_until timestamptz NOT NULL CHECK(isfinite(retention_until) AND retention_until>=expires_at),
    FOREIGN KEY(actor_session_id,tenant_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),
    UNIQUE(actor_session_id,request_id),
    UNIQUE(provider,provider_request_id),
    UNIQUE(tenant_scope_id,id,actor_user_id),
    CHECK((state IN ('creating','pending','processing','unknown') AND terminal_at IS NULL) OR
          (state IN ('succeeded','failed','canceled','expired') AND terminal_at IS NOT NULL)),
    CHECK((state IN ('failed','canceled','expired') AND failure_code IS NOT NULL) OR
          (state NOT IN ('failed','canceled','expired') AND failure_code IS NULL))
);
CREATE UNIQUE INDEX identity_verification_provider_external_session_169_idx
    ON identity_verification_provider_sessions_v1(provider,external_session_id)
    WHERE external_session_id IS NOT NULL;
CREATE INDEX identity_verification_provider_expiry_169_idx
    ON identity_verification_provider_sessions_v1(expires_at,id)
    WHERE state IN ('creating','pending','processing','unknown');

CREATE TABLE identity_verification_provider_attempts_v1 (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    attempt_number bigint NOT NULL CHECK(attempt_number>0),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    outcome text NOT NULL CHECK(outcome IN ('pending','failed','unknown')),
    response_sha256 bytea CHECK(response_sha256 IS NULL OR octet_length(response_sha256)=32),
    signature_sha256 bytea CHECK(signature_sha256 IS NULL OR octet_length(signature_sha256)=32),
    verification_key_id text CHECK(verification_key_id IS NULL OR verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
    finished_at timestamptz NOT NULL CHECK(isfinite(finished_at) AND finished_at>=started_at),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id) ON DELETE RESTRICT,
    UNIQUE(session_id,attempt_number)
);

CREATE TABLE identity_verification_provider_uploads_v1 (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    material_kind text NOT NULL CHECK(material_kind IN (
        'identity_document','liveness_evidence','business_license','legal_person_identity',
        'agent_identity','authorization_letter','supplementary'
    )),
    object_key text NOT NULL CHECK(object_key ~ '^identity-verification/[0-9a-f-]{36}/[0-9a-f-]{36}/[0-9a-f-]{36}/[0-9a-f-]{36}$'),
    object_version text CHECK(object_version IS NULL OR object_version ~ '^[!#-~]{1,512}$'),
    object_sha256 bytea NOT NULL CHECK(octet_length(object_sha256)=32),
    size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 20971520),
    content_type text NOT NULL CHECK(content_type IN ('image/jpeg','image/png','application/pdf','video/mp4')),
    encryption_key_id text NOT NULL CHECK(encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    state text NOT NULL CHECK(state IN ('issued','finalized','erase_pending','erased')),
    revision bigint NOT NULL CHECK(revision>0),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
    finalized_at timestamptz CHECK(finalized_at IS NULL OR isfinite(finalized_at)),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id) ON DELETE RESTRICT,
    UNIQUE(session_id,idempotency_key),
    UNIQUE(session_id,request_id),
    UNIQUE(object_key),
    CHECK((state='issued' AND object_version IS NULL AND finalized_at IS NULL) OR
          (state IN ('finalized','erase_pending','erased') AND object_version IS NOT NULL AND finalized_at IS NOT NULL))
);

CREATE TABLE identity_verification_provider_callbacks_v1 (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    external_session_id text NOT NULL CHECK(external_session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    event_id text NOT NULL CHECK(event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    nonce text NOT NULL CHECK(nonce ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'),
    incoming_state text NOT NULL CHECK(incoming_state IN ('pending','processing','succeeded','failed','canceled','expired')),
    applied boolean NOT NULL,
    payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
    signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
    verification_key_id text NOT NULL CHECK(verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    subject_fingerprint bytea CHECK(subject_fingerprint IS NULL OR octet_length(subject_fingerprint)=32),
    normalized_evidence_sha256 bytea CHECK(normalized_evidence_sha256 IS NULL OR octet_length(normalized_evidence_sha256)=32),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    received_at timestamptz NOT NULL CHECK(isfinite(received_at)),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id) ON DELETE RESTRICT,
    UNIQUE(provider,nonce),
    UNIQUE(provider,event_id)
);

CREATE TABLE identity_verification_provider_settlements_v1 (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('personal_initial','personal_reverification','enterprise')),
    subject_fingerprint bytea NOT NULL CHECK(octet_length(subject_fingerprint)=32),
    normalized_evidence_sha256 bytea NOT NULL CHECK(octet_length(normalized_evidence_sha256)=32),
    provider_callback_id uuid NOT NULL UNIQUE REFERENCES identity_verification_provider_callbacks_v1(id) ON DELETE RESTRICT,
    settled_at timestamptz NOT NULL CHECK(isfinite(settled_at)),
    retention_until timestamptz NOT NULL CHECK(isfinite(retention_until) AND retention_until>=settled_at),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id) ON DELETE RESTRICT
);

CREATE TABLE identity_verification_erase_requests_v1 (
    id uuid PRIMARY KEY,
    upload_id uuid NOT NULL UNIQUE REFERENCES identity_verification_provider_uploads_v1(id) ON DELETE RESTRICT,
    session_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    object_key text NOT NULL,
    object_version text NOT NULL,
    reason_code text NOT NULL CHECK(reason_code IN ('provider_failed','provider_canceled','provider_expired','retention_elapsed')),
    state text NOT NULL CHECK(state IN ('pending','leased','retry_wait','erased')),
    revision bigint NOT NULL CHECK(revision>0),
    attempt_count bigint NOT NULL CHECK(attempt_count>=0),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    lease_token uuid,
    lease_expires_at timestamptz,
    failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    erased_at timestamptz CHECK(erased_at IS NULL OR isfinite(erased_at)),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id) ON DELETE RESTRICT,
    CHECK((state='leased' AND lease_token IS NOT NULL AND lease_expires_at>updated_at) OR
          (state<>'leased' AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CHECK((state='erased' AND erased_at IS NOT NULL AND failure_code IS NULL) OR
          (state<>'erased' AND erased_at IS NULL))
);
CREATE INDEX identity_verification_erase_ready_169_idx
    ON identity_verification_erase_requests_v1(available_at,id) WHERE state IN ('pending','retry_wait');

CREATE TABLE identity_verification_erase_receipts_v1 (
    id uuid PRIMARY KEY,
    erase_request_id uuid NOT NULL UNIQUE REFERENCES identity_verification_erase_requests_v1(id) ON DELETE RESTRICT,
    upload_id uuid NOT NULL UNIQUE REFERENCES identity_verification_provider_uploads_v1(id) ON DELETE RESTRICT,
    object_key_sha256 bytea NOT NULL CHECK(octet_length(object_key_sha256)=32),
    object_version_sha256 bytea NOT NULL CHECK(octet_length(object_version_sha256)=32),
    provider_receipt_sha256 bytea NOT NULL CHECK(octet_length(provider_receipt_sha256)=32),
    erased_at timestamptz NOT NULL CHECK(isfinite(erased_at))
);

CREATE FUNCTION guard_identity_verification_provider_session_169()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('identity-provider-session:'||OLD.id::text,0));
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.actor_user_id,NEW.actor_session_id,NEW.kind,
       NEW.provider,NEW.provider_request_id,NEW.evidence_token_digest,NEW.idempotency_key,NEW.request_id,
       NEW.request_digest_sha256,NEW.created_at,NEW.expires_at,NEW.retention_until) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.actor_user_id,OLD.actor_session_id,OLD.kind,
       OLD.provider,OLD.provider_request_id,OLD.evidence_token_digest,OLD.idempotency_key,OLD.request_id,
       OLD.request_digest_sha256,OLD.created_at,OLD.expires_at,OLD.retention_until) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR NOT (
         (OLD.state='creating' AND NEW.state IN ('pending','failed','expired','unknown')) OR
         (OLD.state='unknown' AND NEW.state IN ('pending','failed','unknown','expired')) OR
         (OLD.state='pending' AND NEW.state IN ('processing','succeeded','failed','canceled','expired')) OR
         (OLD.state='processing' AND NEW.state IN ('succeeded','failed','canceled','expired'))
       ) THEN
        RAISE EXCEPTION 'identity verification provider session transition is invalid' USING ERRCODE='P1691';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_identity_verification_provider_upload_169()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('identity-provider-upload:'||OLD.id::text,0));
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.session_id,NEW.tenant_scope_id,NEW.actor_user_id,NEW.material_kind,
       NEW.object_key,NEW.object_sha256,NEW.size_bytes,NEW.content_type,NEW.encryption_key_id,
       NEW.idempotency_key,NEW.request_id,NEW.created_at,NEW.expires_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.session_id,OLD.tenant_scope_id,OLD.actor_user_id,OLD.material_kind,
       OLD.object_key,OLD.object_sha256,OLD.size_bytes,OLD.content_type,OLD.encryption_key_id,
       OLD.idempotency_key,OLD.request_id,OLD.created_at,OLD.expires_at) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR NOT (
         (OLD.state='issued' AND NEW.state='finalized') OR
         (OLD.state='finalized' AND NEW.state='erase_pending') OR
         (OLD.state='erase_pending' AND NEW.state='erased')
       ) THEN
        RAISE EXCEPTION 'identity verification provider upload transition is invalid' USING ERRCODE='P1692';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_identity_verification_erase_request_169()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('identity-erase-request:'||OLD.id::text,0));
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.upload_id,NEW.session_id,NEW.tenant_scope_id,NEW.actor_user_id,
       NEW.object_key,NEW.object_version,NEW.reason_code,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.upload_id,OLD.session_id,OLD.tenant_scope_id,OLD.actor_user_id,
       OLD.object_key,OLD.object_version,OLD.reason_code,OLD.created_at) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR NOT (
         (OLD.state IN ('pending','retry_wait') AND NEW.state='leased') OR
         (OLD.state='leased' AND NEW.state IN ('retry_wait','erased'))
       ) THEN
        RAISE EXCEPTION 'identity verification erase request transition is invalid' USING ERRCODE='P1693';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_identity_verification_provider_fact_mutation_169()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'identity verification provider facts are append-only' USING ERRCODE='P1694';
END;
$$;

CREATE FUNCTION prevent_identity_verification_provider_truncate_169()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'identity verification provider facts cannot be truncated' USING ERRCODE='P1694';
END;
$$;

CREATE TRIGGER identity_verification_provider_sessions_guard_169
BEFORE UPDATE OR DELETE ON identity_verification_provider_sessions_v1
FOR EACH ROW EXECUTE FUNCTION guard_identity_verification_provider_session_169();
CREATE TRIGGER identity_verification_provider_uploads_guard_169
BEFORE UPDATE OR DELETE ON identity_verification_provider_uploads_v1
FOR EACH ROW EXECUTE FUNCTION guard_identity_verification_provider_upload_169();
CREATE TRIGGER identity_verification_erase_requests_guard_169
BEFORE UPDATE OR DELETE ON identity_verification_erase_requests_v1
FOR EACH ROW EXECUTE FUNCTION guard_identity_verification_erase_request_169();

CREATE TRIGGER identity_verification_provider_attempts_append_only_169
BEFORE UPDATE OR DELETE ON identity_verification_provider_attempts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_provider_fact_mutation_169();
CREATE TRIGGER identity_verification_provider_callbacks_append_only_169
BEFORE UPDATE OR DELETE ON identity_verification_provider_callbacks_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_provider_fact_mutation_169();
CREATE TRIGGER identity_verification_provider_settlements_append_only_169
BEFORE UPDATE OR DELETE ON identity_verification_provider_settlements_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_provider_fact_mutation_169();
CREATE TRIGGER identity_verification_erase_receipts_append_only_169
BEFORE UPDATE OR DELETE ON identity_verification_erase_receipts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_provider_fact_mutation_169();

CREATE TRIGGER identity_verification_provider_sessions_truncate_169
BEFORE TRUNCATE ON identity_verification_provider_sessions_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_provider_attempts_truncate_169
BEFORE TRUNCATE ON identity_verification_provider_attempts_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_provider_uploads_truncate_169
BEFORE TRUNCATE ON identity_verification_provider_uploads_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_provider_callbacks_truncate_169
BEFORE TRUNCATE ON identity_verification_provider_callbacks_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_provider_settlements_truncate_169
BEFORE TRUNCATE ON identity_verification_provider_settlements_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_erase_requests_truncate_169
BEFORE TRUNCATE ON identity_verification_erase_requests_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();
CREATE TRIGGER identity_verification_erase_receipts_truncate_169
BEFORE TRUNCATE ON identity_verification_erase_receipts_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_provider_truncate_169();

REVOKE ALL ON identity_verification_provider_sessions_v1,identity_verification_provider_attempts_v1,
    identity_verification_provider_uploads_v1,identity_verification_provider_callbacks_v1,
    identity_verification_provider_settlements_v1,identity_verification_erase_requests_v1,
    identity_verification_erase_receipts_v1 FROM PUBLIC;

-- Workers use the database clock when materializing retention work; application clocks never decide eligibility.
CREATE FUNCTION enqueue_identity_verification_erase_requests_169(max_rows integer)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE inserted_count integer;
BEGIN
    IF max_rows<1 OR max_rows>1000 THEN
        RAISE EXCEPTION 'invalid identity verification erase batch size' USING ERRCODE='P1695';
    END IF;
    WITH eligible AS (
        SELECT upload.id,upload.session_id,upload.tenant_scope_id,upload.actor_user_id,
               upload.object_key,upload.object_version,
               CASE WHEN session.state='failed' THEN 'provider_failed'
                    WHEN session.state='canceled' THEN 'provider_canceled'
                    WHEN session.state='expired' THEN 'provider_expired'
                    ELSE 'retention_elapsed' END AS reason_code
        FROM identity_verification_provider_uploads_v1 upload
        JOIN identity_verification_provider_sessions_v1 session ON session.id=upload.session_id
        LEFT JOIN identity_verification_erase_requests_v1 erase_request ON erase_request.upload_id=upload.id
        WHERE upload.state='finalized' AND erase_request.id IS NULL AND (
            session.state IN ('failed','canceled','expired') OR
            (session.state='succeeded' AND session.retention_until<=clock_timestamp())
        ) ORDER BY session.retention_until,upload.id FOR UPDATE OF upload SKIP LOCKED LIMIT max_rows
    ), inserted AS (
        INSERT INTO identity_verification_erase_requests_v1(
            id,upload_id,session_id,tenant_scope_id,actor_user_id,object_key,object_version,reason_code,
            state,revision,attempt_count,available_at,created_at,updated_at
        ) SELECT gen_random_uuid(),id,session_id,tenant_scope_id,actor_user_id,object_key,object_version,
                 reason_code,'pending',1,0,clock_timestamp(),clock_timestamp(),clock_timestamp()
          FROM eligible RETURNING upload_id
    )
    UPDATE identity_verification_provider_uploads_v1 upload SET state='erase_pending',revision=revision+1,
           updated_at=clock_timestamp() FROM inserted WHERE upload.id=inserted.upload_id;
    GET DIAGNOSTICS inserted_count=ROW_COUNT;
    RETURN inserted_count;
END;
$$;
