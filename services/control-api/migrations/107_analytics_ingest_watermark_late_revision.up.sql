LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    -- REQUIRED_MIGRATION_106_INTEGRATION_SHA256=9af7dcdf823cf088718e8573059d4f6ac6bc6ba4852a7d954db31d093fdab861
    IF (SELECT count(*) FROM schema_migrations) <> 106 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 106 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=106 AND migration_id='106_dns_provider_credential_lifecycle'
          AND checksum_sha256='097ca7d3fcdf878ff11cc891e8a8b05abe3dfd923b9153fdc15ee616d3415adf'
          AND down_checksum_sha256='08ce9a086b6b9be1a78a466e62303bafa76d7cdd6cef060b001d4f0db14dd1df'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 107 requires the exact verified 106 release head'
            USING ERRCODE='P1070';
    END IF;
END;
$$;

LOCK TABLE schema_migrations, analytics_history_streams, analytics_ingest_receipts
IN ACCESS EXCLUSIVE MODE;

CREATE TABLE analytics_ingest_watermarks_107 (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    installation_id text NOT NULL
        REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('access.v1','security.v1')),
    history_epoch uuid NOT NULL
        REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT,
    watermark_sequence numeric(20,0) NOT NULL CHECK (
        watermark_sequence BETWEEN 0 AND 18446744073709551615
    ),
    watermark_at timestamptz NOT NULL CHECK (isfinite(watermark_at)),
    last_event_at timestamptz NOT NULL CHECK (isfinite(last_event_at)),
    allowed_lateness interval NOT NULL CHECK (
        allowed_lateness > interval '0 seconds' AND
        allowed_lateness <= interval '24 hours'
    ),
    finalized_through timestamptz NOT NULL CHECK (isfinite(finalized_through)),
    revision numeric(20,0) NOT NULL CHECK (
        revision BETWEEN 1 AND 18446744073709551615
    ),
    dependency_state text NOT NULL CHECK (
        dependency_state IN ('ready','unknown','unavailable')
    ),
    last_known_good_sequence numeric(20,0) NOT NULL CHECK (
        last_known_good_sequence BETWEEN 0 AND 18446744073709551615
    ),
    last_known_good_at timestamptz NOT NULL CHECK (isfinite(last_known_good_at)),
    last_known_good_revision numeric(20,0) NOT NULL CHECK (
        last_known_good_revision BETWEEN 1 AND 18446744073709551615
    ),
    last_known_good_digest bytea NOT NULL CHECK (octet_length(last_known_good_digest)=32),
    last_event_id text CHECK (
        last_event_id IS NULL OR
        (last_event_id=btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128 AND
         last_event_id !~ '[[:cntrl:]]')
    ),
    last_receipt_identity_sha256 bytea CHECK (
        last_receipt_identity_sha256 IS NULL OR octet_length(last_receipt_identity_sha256)=32
    ),
    last_event_digest_sha256 bytea CHECK (
        last_event_digest_sha256 IS NULL OR octet_length(last_event_digest_sha256)=32
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY (tenant_id,installation_id,kind),
    CHECK (finalized_through<=watermark_at),
    CHECK (last_event_at<=watermark_at),
    CHECK (last_known_good_sequence<=watermark_sequence),
    CHECK (last_known_good_revision<=revision),
    CHECK (last_known_good_at<=watermark_at),
    CHECK ((last_event_id IS NULL) = (last_receipt_identity_sha256 IS NULL AND
           last_event_digest_sha256 IS NULL))
);

COMMENT ON TABLE analytics_ingest_watermarks_107 IS
    'Authoritative tenant/installation/kind event-time watermark. It is the durable LKG fence for analytics writes and queries.';

CREATE TABLE analytics_ingest_watermark_decisions_107 (
    decision_id uuid PRIMARY KEY CHECK (
        decision_id<>'00000000-0000-0000-0000-000000000000'::uuid
    ),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    installation_id text NOT NULL
        REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('access.v1','security.v1')),
    history_epoch uuid NOT NULL
        REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT,
    event_id text NOT NULL CHECK (
        event_id=btrim(event_id) AND char_length(event_id) BETWEEN 1 AND 128 AND
        event_id !~ '[[:cntrl:]]'
    ),
    idempotency_key text NOT NULL CHECK (
        idempotency_key=btrim(idempotency_key) AND
        idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'
    ),
    receipt_identity_sha256 bytea NOT NULL CHECK (octet_length(receipt_identity_sha256)=32),
    event_digest_sha256 bytea NOT NULL CHECK (octet_length(event_digest_sha256)=32),
    event_sequence numeric(20,0) NOT NULL CHECK (
        event_sequence BETWEEN 1 AND 18446744073709551615
    ),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    decision text NOT NULL CHECK (decision IN (
        'accepted','replay','late_revision','baseline_off','rejected'
    )),
    reason text NOT NULL CHECK (reason IN (
        'baseline_off','accepted','replay','late_revision','finalized_window',
        'late_revision_exceeded','out_of_order','digest_conflict',
        'dependency_unknown','dependency_unavailable'
    )),
    resulting_watermark_sequence numeric(20,0) NOT NULL CHECK (
        resulting_watermark_sequence BETWEEN 0 AND 18446744073709551615
    ),
    resulting_revision numeric(20,0) NOT NULL CHECK (
        resulting_revision BETWEEN 1 AND 18446744073709551615
    ),
    resulting_finalized_through timestamptz NOT NULL CHECK (isfinite(resulting_finalized_through)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (tenant_id,installation_id,kind,event_id),
    UNIQUE (tenant_id,installation_id,kind,idempotency_key),
    FOREIGN KEY (tenant_id,installation_id,kind)
        REFERENCES analytics_ingest_watermarks_107(tenant_id,installation_id,kind)
        ON DELETE RESTRICT,
    CHECK (resulting_finalized_through<=occurred_at OR decision IN ('rejected','replay','baseline_off'))
);

CREATE INDEX analytics_ingest_watermark_decisions_107_query_idx
    ON analytics_ingest_watermark_decisions_107(
        tenant_id,installation_id,kind,occurred_at DESC,decision_id DESC
    );

-- 098's immutable generation identity is canonicalized before a receipt can be admitted.
CREATE FUNCTION analytics_history_generation_digest_107(
    p_installation_id text,
    p_nats_domain text,
    p_stream_name text,
    p_durable_name text,
    p_stream_created_unix_nano numeric,
    p_consumer_created_unix_nano numeric,
    p_history_epoch uuid,
    p_history_start_sequence numeric,
    p_history_start_at timestamptz,
    p_legacy_baseline_kind text,
    p_legacy_baseline_at timestamptz,
    p_legacy_baseline_sha256 bytea
)
RETURNS bytea
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT sha256(convert_to(concat_ws(E'\x1f',
        'cdnca.analytics-history-generation/v1',
        COALESCE(p_installation_id,''), COALESCE(p_nats_domain,''),
        COALESCE(p_stream_name,''), COALESCE(p_durable_name,''),
        COALESCE(p_stream_created_unix_nano::text,''),
        COALESCE(p_consumer_created_unix_nano::text,''),
        COALESCE(p_history_epoch::text,''),
        COALESCE(p_history_start_sequence::text,''),
        COALESCE(extract(epoch FROM p_history_start_at)::text,''),
        COALESCE(p_legacy_baseline_kind,''),
        COALESCE(extract(epoch FROM p_legacy_baseline_at)::text,''),
        COALESCE(encode(p_legacy_baseline_sha256,'hex'),'')
    ), 'UTF8'))
$$;

CREATE FUNCTION guard_analytics_ingest_watermark_107()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    generation analytics_history_streams%ROWTYPE;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT * INTO generation FROM analytics_history_streams
        WHERE history_epoch=NEW.history_epoch FOR SHARE;
        IF NOT FOUND OR generation.retired_at IS NOT NULL OR
           generation.installation_id IS DISTINCT FROM NEW.installation_id OR
           NEW.watermark_sequence<>generation.history_start_sequence-1 OR
           NEW.revision<>1 OR NEW.updated_at<>NEW.created_at OR
           NEW.last_event_at<>NEW.watermark_at OR
           NEW.last_known_good_sequence<>NEW.watermark_sequence OR
           NEW.last_known_good_revision<>NEW.revision OR
           NEW.last_known_good_at<>NEW.watermark_at THEN
            RAISE EXCEPTION 'analytics watermark requires the active authoritative history generation'
                USING ERRCODE='P1073';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'analytics watermarks are append-only state facts' USING ERRCODE='P1072';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
       NEW.kind IS DISTINCT FROM OLD.kind OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.history_epoch IS DISTINCT FROM OLD.history_epoch OR
       NEW.allowed_lateness IS DISTINCT FROM OLD.allowed_lateness THEN
        RAISE EXCEPTION 'analytics watermark identity and lateness policy are immutable'
            USING ERRCODE='P1072';
    END IF;
    IF NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at OR
       NEW.watermark_sequence<OLD.watermark_sequence OR
       NEW.watermark_at<OLD.watermark_at OR
       NEW.last_event_at<OLD.last_event_at OR
       NEW.finalized_through<OLD.finalized_through OR
       NEW.last_known_good_sequence<OLD.last_known_good_sequence OR
       NEW.last_known_good_revision<OLD.last_known_good_revision OR
       NEW.last_known_good_at<OLD.last_known_good_at THEN
        RAISE EXCEPTION 'analytics watermark revision and finalized boundary must advance monotonically'
            USING ERRCODE='P1072';
    END IF;
    IF NEW.dependency_state IN ('unknown','unavailable') AND
       (NEW.watermark_sequence<>NEW.last_known_good_sequence OR
        NEW.watermark_at<>NEW.last_known_good_at OR
        NEW.last_event_at<>NEW.last_known_good_at) THEN
        RAISE EXCEPTION 'analytics watermark dependency outage must preserve the last known good state'
            USING ERRCODE='P1073';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_analytics_ingest_watermark_decision_107()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    watermark analytics_ingest_watermarks_107%ROWTYPE;
    generation analytics_history_streams%ROWTYPE;
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'analytics watermark decisions are append-only' USING ERRCODE='P1072';
    END IF;
    SELECT * INTO watermark FROM analytics_ingest_watermarks_107
    WHERE tenant_id=NEW.tenant_id AND installation_id=NEW.installation_id AND kind=NEW.kind
    FOR SHARE;
    SELECT * INTO generation FROM analytics_history_streams
    WHERE history_epoch=NEW.history_epoch FOR SHARE;
    IF NOT FOUND OR generation.retired_at IS NOT NULL OR
       generation.installation_id IS DISTINCT FROM NEW.installation_id OR
       watermark.history_epoch IS DISTINCT FROM NEW.history_epoch OR
       NEW.resulting_revision IS DISTINCT FROM watermark.revision OR
       NEW.resulting_watermark_sequence>watermark.watermark_sequence OR
       NEW.resulting_finalized_through>watermark.finalized_through THEN
        RAISE EXCEPTION 'analytics watermark decision is not bound to the authoritative history state'
            USING ERRCODE='P1073';
    END IF;
    IF NEW.decision='late_revision' AND
       (NEW.occurred_at>=watermark.watermark_at OR
        NEW.occurred_at<=watermark.finalized_through) THEN
        RAISE EXCEPTION 'analytics late revision is outside the unfinalized lateness window'
            USING ERRCODE='P1073';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_analytics_ingest_watermark_truncate_107()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics watermarks cannot be truncated' USING ERRCODE='P1072';
END;
$$;

CREATE FUNCTION prevent_analytics_ingest_watermark_decision_truncate_107()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics watermark decisions cannot be truncated' USING ERRCODE='P1072';
END;
$$;

CREATE TRIGGER analytics_ingest_watermarks_append_only_107
BEFORE INSERT OR UPDATE OR DELETE ON analytics_ingest_watermarks_107
FOR EACH ROW EXECUTE FUNCTION guard_analytics_ingest_watermark_107();

CREATE TRIGGER analytics_ingest_watermarks_truncate_guard_107
BEFORE TRUNCATE ON analytics_ingest_watermarks_107
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_ingest_watermark_truncate_107();

CREATE TRIGGER analytics_ingest_watermark_decisions_truncate_guard_107
BEFORE TRUNCATE ON analytics_ingest_watermark_decisions_107
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_ingest_watermark_decision_truncate_107();

CREATE FUNCTION analytics_ingest_commit_watermark_107(
    p_tenant_id uuid,
    p_installation_id text,
    p_kind text,
    p_history_epoch uuid,
    p_event_id text,
    p_idempotency_key text,
    p_receipt_identity_sha256 bytea,
    p_event_digest_sha256 bytea,
    p_event_sequence numeric,
    p_occurred_at timestamptz,
    p_allowed_lateness interval,
    p_dependency_state text,
    p_at timestamptz
)
RETURNS TABLE(decision_id uuid, decision text, reason text, revision numeric)
LANGUAGE plpgsql
AS $$
DECLARE
    watermark analytics_ingest_watermarks_107%ROWTYPE;
    generation analytics_history_streams%ROWTYPE;
    previous_decision analytics_ingest_watermark_decisions_107%ROWTYPE;
    durable_receipt analytics_ingest_receipts%ROWTYPE;
    next_decision_id uuid := gen_random_uuid();
    next_revision numeric(20,0);
    next_sequence numeric(20,0);
    next_watermark_at timestamptz;
    next_finalized_through timestamptz;
    current_generation_digest bytea;
    outcome text;
    outcome_reason text;
    late boolean;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_installation_id IS NULL OR p_installation_id<>btrim(p_installation_id) OR
       char_length(p_installation_id) NOT BETWEEN 1 AND 128 OR
       p_kind NOT IN ('access.v1','security.v1') OR p_history_epoch IS NULL OR
       p_event_id IS NULL OR p_event_id<>btrim(p_event_id) OR
       char_length(p_event_id) NOT BETWEEN 1 AND 128 OR p_event_id ~ '[[:cntrl:]]' OR
       p_idempotency_key IS NULL OR p_idempotency_key !~ '^[A-Za-z0-9._:-]{1,128}$' OR
       p_receipt_identity_sha256 IS NULL OR octet_length(p_receipt_identity_sha256)<>32 OR
       p_event_digest_sha256 IS NULL OR octet_length(p_event_digest_sha256)<>32 OR
       p_event_sequence IS NULL OR p_event_sequence NOT BETWEEN 1 AND 18446744073709551615 OR
       p_occurred_at IS NULL OR NOT isfinite(p_occurred_at) OR
       p_allowed_lateness IS NULL OR p_allowed_lateness<=interval '0 seconds' OR
       p_allowed_lateness>interval '24 hours' OR p_dependency_state NOT IN ('ready','unknown','unavailable') OR
       p_at IS NULL OR NOT isfinite(p_at) THEN
        RAISE EXCEPTION 'analytics watermark commit precondition failed' USING ERRCODE='P1073';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        p_tenant_id::text||chr(31)||p_installation_id||chr(31)||p_kind,107));
    SELECT * INTO generation FROM analytics_history_streams
    WHERE history_epoch=p_history_epoch FOR SHARE;
    IF NOT FOUND OR generation.retired_at IS NOT NULL OR
       generation.installation_id IS DISTINCT FROM p_installation_id THEN
        RAISE EXCEPTION 'analytics watermark requires the active authoritative history generation'
            USING ERRCODE='P1073';
    END IF;
    IF p_event_sequence<generation.history_start_sequence THEN
        RAISE EXCEPTION 'analytics watermark receipt sequence is before the authoritative history generation'
            USING ERRCODE='P1073';
    END IF;
    current_generation_digest:=analytics_history_generation_digest_107(
        generation.installation_id,generation.nats_domain,generation.stream_name,
        generation.durable_name,generation.stream_created_unix_nano,
        generation.consumer_created_unix_nano,generation.history_epoch,
        generation.history_start_sequence,generation.history_start_at,
        generation.legacy_baseline_kind,generation.legacy_baseline_at,
        generation.legacy_baseline_sha256
    );
    SELECT * INTO durable_receipt FROM analytics_ingest_receipts
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_event_sequence FOR SHARE;
    IF NOT FOUND OR durable_receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256 OR
       durable_receipt.canonical_event_sha256 IS DISTINCT FROM p_event_digest_sha256 OR
       durable_receipt.generation_sha256 IS DISTINCT FROM current_generation_digest THEN
        RAISE EXCEPTION 'analytics watermark commit does not bind the durable ingest receipt'
            USING ERRCODE='P1073';
    END IF;
    SELECT * INTO watermark FROM analytics_ingest_watermarks_107
    WHERE tenant_id=p_tenant_id AND installation_id=p_installation_id AND kind=p_kind FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO analytics_ingest_watermarks_107(
            tenant_id,installation_id,kind,history_epoch,watermark_sequence,watermark_at,
            last_event_at,allowed_lateness,finalized_through,revision,dependency_state,
            last_known_good_sequence,last_known_good_at,last_known_good_revision,last_known_good_digest,
            created_at,updated_at
        ) VALUES (
            p_tenant_id,p_installation_id,p_kind,p_history_epoch,generation.history_start_sequence-1,
            p_occurred_at-p_allowed_lateness,p_occurred_at-p_allowed_lateness,p_allowed_lateness,
            p_occurred_at-p_allowed_lateness,1,
            p_dependency_state,generation.history_start_sequence-1,p_occurred_at-p_allowed_lateness,1,
            decode(repeat('00',32),'hex'),p_at,p_at
        );
        SELECT * INTO watermark FROM analytics_ingest_watermarks_107
        WHERE tenant_id=p_tenant_id AND installation_id=p_installation_id AND kind=p_kind FOR UPDATE;
    END IF;
    IF watermark.history_epoch IS DISTINCT FROM p_history_epoch OR
       watermark.allowed_lateness IS DISTINCT FROM p_allowed_lateness THEN
        RAISE EXCEPTION 'analytics watermark generation or lateness policy conflicts with the durable authority'
            USING ERRCODE='P1073';
    END IF;
    SELECT * INTO previous_decision FROM analytics_ingest_watermark_decisions_107
    WHERE tenant_id=p_tenant_id AND installation_id=p_installation_id AND kind=p_kind AND
          (event_id=p_event_id OR idempotency_key=p_idempotency_key) FOR SHARE;
    IF FOUND THEN
        IF previous_decision.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256 OR
           previous_decision.event_digest_sha256 IS DISTINCT FROM p_event_digest_sha256 OR
           previous_decision.event_id IS DISTINCT FROM p_event_id OR
           previous_decision.idempotency_key IS DISTINCT FROM p_idempotency_key THEN
            RAISE EXCEPTION 'analytics watermark receipt or idempotency digest conflicts with the durable fact'
                USING ERRCODE='P1073';
        END IF;
        decision_id:=previous_decision.decision_id;
        decision:='replay';
        reason:='same receipt and digest replay';
        revision:=previous_decision.resulting_revision;
        RETURN NEXT;
        RETURN;
    END IF;
    IF p_dependency_state IN ('unknown','unavailable') OR
       (watermark.dependency_state IN ('unknown','unavailable') AND p_dependency_state<>'ready') THEN
        IF p_at<=watermark.updated_at THEN
            RAISE EXCEPTION 'analytics watermark commit time regressed' USING ERRCODE='P1073';
        END IF;
        IF p_at>watermark.updated_at THEN
            UPDATE analytics_ingest_watermarks_107
            SET dependency_state=p_dependency_state,revision=watermark.revision+1,updated_at=p_at
            WHERE tenant_id=p_tenant_id AND installation_id=p_installation_id AND kind=p_kind;
            watermark.revision:=watermark.revision+1;
            watermark.dependency_state:=p_dependency_state;
        END IF;
        outcome:='rejected';
        outcome_reason:=CASE WHEN p_dependency_state='unknown' OR watermark.dependency_state='unknown'
            THEN 'dependency_unknown' ELSE 'dependency_unavailable' END;
        next_revision:=watermark.revision;
        next_sequence:=watermark.watermark_sequence;
        next_finalized_through:=watermark.finalized_through;
    ELSE
        IF p_at<=watermark.updated_at THEN
            RAISE EXCEPTION 'analytics watermark commit time regressed' USING ERRCODE='P1073';
        END IF;
        late:=p_occurred_at<watermark.watermark_at;
        IF p_occurred_at<=watermark.finalized_through THEN
            outcome:='rejected';
            outcome_reason:='finalized_window';
        ELSIF late AND watermark.watermark_at-p_occurred_at>watermark.allowed_lateness THEN
            outcome:='rejected';
            outcome_reason:='late_revision_exceeded';
        ELSIF NOT late AND p_event_sequence<=watermark.watermark_sequence THEN
            outcome:='rejected';
            outcome_reason:='out_of_order';
        ELSE
            outcome:=CASE WHEN late THEN 'late_revision' ELSE 'accepted' END;
            outcome_reason:=CASE WHEN late THEN 'late_revision' ELSE 'accepted' END;
            next_sequence:=GREATEST(watermark.watermark_sequence,p_event_sequence);
            next_watermark_at:=GREATEST(watermark.watermark_at,p_occurred_at);
            next_finalized_through:=GREATEST(watermark.finalized_through,p_occurred_at-watermark.allowed_lateness);
            next_revision:=watermark.revision+1;
            UPDATE analytics_ingest_watermarks_107
            SET watermark_sequence=next_sequence,watermark_at=next_watermark_at,
                finalized_through=next_finalized_through,revision=next_revision,
                last_event_at=next_watermark_at,dependency_state=p_dependency_state,
                last_known_good_sequence=next_sequence,
                last_known_good_at=next_watermark_at,last_known_good_revision=next_revision,
                last_known_good_digest=p_event_digest_sha256,last_event_id=p_event_id,
                last_receipt_identity_sha256=p_receipt_identity_sha256,
                last_event_digest_sha256=p_event_digest_sha256,updated_at=p_at
            WHERE tenant_id=p_tenant_id AND installation_id=p_installation_id AND kind=p_kind;
        END IF;
        IF next_revision IS NULL THEN
            next_revision:=watermark.revision;
            next_sequence:=watermark.watermark_sequence;
            next_finalized_through:=watermark.finalized_through;
        END IF;
    END IF;
    INSERT INTO analytics_ingest_watermark_decisions_107(
        decision_id,tenant_id,installation_id,kind,history_epoch,event_id,idempotency_key,
        receipt_identity_sha256,event_digest_sha256,event_sequence,occurred_at,decision,reason,
        resulting_watermark_sequence,resulting_revision,resulting_finalized_through,created_at
    ) VALUES (
        next_decision_id,p_tenant_id,p_installation_id,p_kind,p_history_epoch,p_event_id,p_idempotency_key,
        p_receipt_identity_sha256,p_event_digest_sha256,p_event_sequence,p_occurred_at,outcome,outcome_reason,
        next_sequence,next_revision,next_finalized_through,p_at
    );
    decision_id:=next_decision_id;
    decision:=outcome;
    reason:=outcome_reason;
    revision:=next_revision;
    RETURN NEXT;
END;
$$;

CREATE TRIGGER analytics_ingest_watermark_decisions_guard_107
BEFORE INSERT OR UPDATE OR DELETE ON analytics_ingest_watermark_decisions_107
FOR EACH ROW EXECUTE FUNCTION guard_analytics_ingest_watermark_decision_107();

REVOKE ALL ON analytics_ingest_watermarks_107,analytics_ingest_watermark_decisions_107 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_ingest_watermark_107() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_ingest_watermark_decision_107() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_ingest_watermark_truncate_107() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_ingest_watermark_decision_truncate_107() FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_ingest_commit_watermark_107(uuid,text,text,uuid,text,text,bytea,bytea,numeric,timestamptz,interval,text,timestamptz) FROM PUBLIC;
