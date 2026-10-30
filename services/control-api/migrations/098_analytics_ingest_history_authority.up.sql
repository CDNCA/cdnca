LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 97 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 97 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=97 AND migration_id='097_upgrade_license_receipt_delivery'
          AND checksum_sha256='38e154e329fb72b2664c84b777fbe63b9ba299e1a73397e7f7fddbc9a7bddd11'
          AND down_checksum_sha256='2a741f9196025c13982a0cba09091e6dc70f2903d374caae3593e178c14b6552'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 098 requires the exact verified 097 release head'
            USING ERRCODE = 'P9800';
    END IF;
END;
$$;

CREATE TABLE analytics_ingest_receipts (
    history_epoch uuid NOT NULL,
    stream_sequence numeric(20,0) NOT NULL,
    receipt_identity_sha256 bytea NOT NULL,
    generation_sha256 bytea NOT NULL,
    message_id text NOT NULL,
    payload_sha256 bytea NOT NULL,
    canonical_event_sha256 bytea NOT NULL,
    clickhouse_token text NOT NULL,
    state text NOT NULL CHECK (state IN ('received','prepared','broker_ack_observed')),
    received_at timestamptz NOT NULL,
    prepared_at timestamptz,
    broker_ack_observed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (history_epoch,stream_sequence),
    UNIQUE (clickhouse_token),
    FOREIGN KEY (history_epoch)
        REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT,
    CHECK (stream_sequence BETWEEN 1 AND 18446744073709551615),
    CHECK (octet_length(receipt_identity_sha256)=32),
    CHECK (octet_length(generation_sha256)=32),
    CHECK (octet_length(payload_sha256)=32),
    CHECK (octet_length(canonical_event_sha256)=32),
    CHECK (clickhouse_token ~ '^analytics-history-v1-[0-9a-f]{64}$'),
    CHECK (message_id=btrim(message_id) AND char_length(message_id) BETWEEN 1 AND 256),
    CHECK (isfinite(received_at) AND isfinite(created_at) AND isfinite(updated_at)),
    CHECK (prepared_at IS NULL OR isfinite(prepared_at)),
    CHECK (broker_ack_observed_at IS NULL OR isfinite(broker_ack_observed_at)),
    CHECK (updated_at>=created_at),
    CHECK (prepared_at IS NULL OR prepared_at>=received_at),
    CHECK (broker_ack_observed_at IS NULL OR
           (prepared_at IS NOT NULL AND broker_ack_observed_at>=prepared_at)),
    CHECK (
        (state='received' AND prepared_at IS NULL AND broker_ack_observed_at IS NULL) OR
        (state='prepared' AND prepared_at IS NOT NULL AND broker_ack_observed_at IS NULL) OR
        (state='broker_ack_observed' AND prepared_at IS NOT NULL AND broker_ack_observed_at IS NOT NULL)
    )
);

CREATE TABLE analytics_history_recoveries (
    recovery_id uuid PRIMARY KEY CHECK (
        recovery_id<>'00000000-0000-0000-0000-000000000000'::uuid
    ),
    history_epoch uuid NOT NULL,
    reason text NOT NULL,
    scheduled_at timestamptz NOT NULL,
    claimed_by text,
    claim_token uuid,
    claimed_at timestamptz,
    lease_expires_at timestamptz,
    reconciled_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (history_epoch)
        REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT,
    CHECK (reason=btrim(reason) AND char_length(reason) BETWEEN 1 AND 128 AND
           reason !~ '[[:cntrl:]]'),
    CHECK (isfinite(scheduled_at) AND isfinite(created_at) AND isfinite(updated_at)),
    CHECK (claimed_at IS NULL OR isfinite(claimed_at)),
    CHECK (lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    CHECK (reconciled_at IS NULL OR isfinite(reconciled_at)),
    CHECK (completed_at IS NULL OR isfinite(completed_at)),
    CHECK (updated_at>=created_at),
    CHECK (claimed_at IS NULL OR claimed_at>=scheduled_at),
    CHECK (claim_token IS NULL OR
           claim_token<>'00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (
        (claim_token IS NULL AND claimed_by IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL) OR
        (claim_token IS NOT NULL AND claimed_by IS NOT NULL AND claimed_at IS NOT NULL AND
         lease_expires_at IS NOT NULL AND lease_expires_at>claimed_at)
    ),
    CHECK (claimed_by IS NULL OR
           (claimed_by=btrim(claimed_by) AND char_length(claimed_by) BETWEEN 1 AND 128 AND
            claimed_by !~ '[[:cntrl:]]')),
    CHECK (reconciled_at IS NULL OR (reconciled_at>=scheduled_at AND
           (claimed_at IS NULL OR reconciled_at>=claimed_at))),
    CHECK (completed_at IS NULL OR (reconciled_at IS NOT NULL AND completed_at>=reconciled_at)),
    CHECK (completed_at IS NULL OR (claim_token IS NULL AND claimed_by IS NULL AND
           claimed_at IS NULL AND lease_expires_at IS NULL))
);

CREATE UNIQUE INDEX analytics_history_recoveries_one_active_098_idx
    ON analytics_history_recoveries(history_epoch)
    WHERE completed_at IS NULL;

CREATE FUNCTION guard_analytics_ingest_receipt_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    start_sequence numeric(20,0);
    retired_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT history_start_sequence, analytics_history_streams.retired_at
        INTO start_sequence, retired_at
        FROM analytics_history_streams
        WHERE history_epoch=NEW.history_epoch;
        IF NOT FOUND THEN
            RETURN NEW;
        END IF;
        IF retired_at IS NOT NULL OR NEW.stream_sequence < start_sequence THEN
            RAISE EXCEPTION 'analytics ingest receipt sequence is outside the active history generation'
                USING ERRCODE = 'P9803';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.history_epoch IS DISTINCT FROM OLD.history_epoch OR
       NEW.stream_sequence IS DISTINCT FROM OLD.stream_sequence OR
       NEW.receipt_identity_sha256 IS DISTINCT FROM OLD.receipt_identity_sha256 OR
       NEW.generation_sha256 IS DISTINCT FROM OLD.generation_sha256 OR
       NEW.message_id IS DISTINCT FROM OLD.message_id OR
       NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256 OR
       NEW.canonical_event_sha256 IS DISTINCT FROM OLD.canonical_event_sha256 OR
       NEW.clickhouse_token IS DISTINCT FROM OLD.clickhouse_token OR
       NEW.received_at IS DISTINCT FROM OLD.received_at OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       (OLD.prepared_at IS NOT NULL AND NEW.prepared_at IS DISTINCT FROM OLD.prepared_at) OR
       (OLD.broker_ack_observed_at IS NOT NULL AND
        NEW.broker_ack_observed_at IS DISTINCT FROM OLD.broker_ack_observed_at) THEN
        RAISE EXCEPTION 'analytics ingest receipt identity and digests are immutable'
            USING ERRCODE = 'P9802';
    END IF;
    IF NEW.updated_at <= OLD.updated_at OR
       (OLD.state='received' AND NEW.state NOT IN ('received','prepared')) OR
       (OLD.state='prepared' AND NEW.state NOT IN ('prepared','broker_ack_observed')) OR
       (OLD.state='broker_ack_observed' AND NEW.state<>'broker_ack_observed') THEN
        RAISE EXCEPTION 'analytics ingest receipt state is not monotonic'
            USING ERRCODE = 'P9802';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_analytics_ingest_receipt_delete_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics ingest receipts are append-only'
        USING ERRCODE = 'P9802';
END;
$$;

CREATE FUNCTION prevent_analytics_ingest_receipt_truncate_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics ingest receipts cannot be truncated'
        USING ERRCODE = 'P9802';
END;
$$;

CREATE TRIGGER analytics_ingest_receipts_guard_098
BEFORE INSERT OR UPDATE ON analytics_ingest_receipts
FOR EACH ROW EXECUTE FUNCTION guard_analytics_ingest_receipt_098();

CREATE TRIGGER analytics_ingest_receipts_delete_guard_098
BEFORE DELETE ON analytics_ingest_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_analytics_ingest_receipt_delete_098();

CREATE TRIGGER analytics_ingest_receipts_truncate_guard_098
BEFORE TRUNCATE ON analytics_ingest_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_ingest_receipt_truncate_098();

CREATE FUNCTION analytics_ingest_mark_prepared_098(
    p_history_epoch uuid,
    p_stream_sequence numeric,
    p_receipt_identity_sha256 bytea,
    p_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    receipt analytics_ingest_receipts%ROWTYPE;
    generation analytics_history_streams%ROWTYPE;
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_receipt_identity_sha256 IS NULL OR
       octet_length(p_receipt_identity_sha256)<>32 THEN
        RAISE EXCEPTION 'analytics ingest preparation precondition failed' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO generation FROM analytics_history_streams
    WHERE history_epoch=p_history_epoch FOR UPDATE;
    IF NOT FOUND OR generation.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'analytics ingest history generation is unavailable' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO receipt FROM analytics_ingest_receipts
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence FOR UPDATE;
    IF NOT FOUND OR receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256 THEN
        RAISE EXCEPTION 'analytics ingest receipt identity does not match' USING ERRCODE = 'P9803';
    END IF;
    IF receipt.state IN ('prepared','broker_ack_observed') THEN
        RETURN;
    END IF;
    IF receipt.state<>'received' OR p_stream_sequence<>generation.prepared_stream_floor+1 OR
       p_at<=generation.updated_at THEN
        RAISE EXCEPTION 'analytics ingest preparation sequence is not contiguous' USING ERRCODE = 'P9803';
    END IF;
    UPDATE analytics_ingest_receipts
    SET state='prepared',prepared_at=p_at,updated_at=p_at
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence;
    UPDATE analytics_history_streams
    SET prepared_stream_floor=p_stream_sequence,
        revision=revision+1,
        last_reconciled_at=GREATEST(last_reconciled_at,p_at),
        updated_at=p_at
    WHERE history_epoch=p_history_epoch;
END;
$$;

CREATE FUNCTION analytics_ingest_mark_broker_ack_observed_098(
    p_history_epoch uuid,
    p_stream_sequence numeric,
    p_receipt_identity_sha256 bytea,
    p_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    receipt analytics_ingest_receipts%ROWTYPE;
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_receipt_identity_sha256 IS NULL OR
       octet_length(p_receipt_identity_sha256)<>32 THEN
        RAISE EXCEPTION 'analytics ingest broker acknowledgement precondition failed' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO receipt FROM analytics_ingest_receipts
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence FOR UPDATE;
    IF NOT FOUND OR receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256 THEN
        RAISE EXCEPTION 'analytics ingest receipt identity does not match' USING ERRCODE = 'P9803';
    END IF;
    IF receipt.state='broker_ack_observed' THEN
        RETURN;
    END IF;
    IF receipt.state<>'prepared' OR p_at<=receipt.updated_at THEN
        RAISE EXCEPTION 'analytics ingest broker acknowledgement requires preparation' USING ERRCODE = 'P9803';
    END IF;
    UPDATE analytics_ingest_receipts
    SET state='broker_ack_observed',broker_ack_observed_at=p_at,updated_at=p_at
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence;
END;
$$;

CREATE FUNCTION guard_analytics_history_recovery_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM analytics_history_streams
        WHERE history_epoch=NEW.history_epoch AND retired_at IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'analytics history recovery requires an active generation'
                USING ERRCODE = 'P9803';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.recovery_id IS DISTINCT FROM OLD.recovery_id OR
       NEW.history_epoch IS DISTINCT FROM OLD.history_epoch OR
       NEW.reason IS DISTINCT FROM OLD.reason OR
       NEW.scheduled_at IS DISTINCT FROM OLD.scheduled_at OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'analytics history recovery identity is immutable' USING ERRCODE = 'P9802';
    END IF;
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed analytics history recoveries are immutable' USING ERRCODE = 'P9802';
    END IF;
    IF NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'analytics history recovery update time must advance' USING ERRCODE = 'P9802';
    END IF;
    IF NEW.completed_at IS NOT NULL THEN
        IF OLD.claim_token IS NULL OR NEW.claim_token IS NOT NULL OR NEW.reconciled_at IS NULL THEN
            RAISE EXCEPTION 'analytics history recovery completion is not fenced' USING ERRCODE = 'P9803';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.claim_token IS DISTINCT FROM OLD.claim_token THEN
        IF NEW.claim_token IS NULL THEN
            RAISE EXCEPTION 'analytics history recovery claim transition is invalid' USING ERRCODE = 'P9802';
        ELSIF OLD.claim_token IS NOT NULL AND OLD.lease_expires_at>NEW.claimed_at THEN
            RAISE EXCEPTION 'analytics history recovery lease is still active' USING ERRCODE = 'P9803';
        END IF;
        IF NEW.reconciled_at IS NOT NULL THEN
            RAISE EXCEPTION 'analytics history recovery takeover must clear reconciliation' USING ERRCODE = 'P9802';
        END IF;
    ELSIF NEW.reconciled_at IS DISTINCT FROM OLD.reconciled_at AND
          (NEW.claim_token IS NULL OR NEW.reconciled_at IS NULL OR
           NEW.reconciled_at<OLD.scheduled_at OR NEW.reconciled_at>NEW.lease_expires_at) THEN
        RAISE EXCEPTION 'analytics history recovery reconciliation is not fenced' USING ERRCODE = 'P9803';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_analytics_history_recovery_delete_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics history recoveries are append-only' USING ERRCODE = 'P9802';
END;
$$;

CREATE FUNCTION prevent_analytics_history_recovery_truncate_098()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics history recoveries cannot be truncated' USING ERRCODE = 'P9802';
END;
$$;

CREATE TRIGGER analytics_history_recoveries_guard_098
BEFORE INSERT OR UPDATE ON analytics_history_recoveries
FOR EACH ROW EXECUTE FUNCTION guard_analytics_history_recovery_098();

CREATE TRIGGER analytics_history_recoveries_delete_guard_098
BEFORE DELETE ON analytics_history_recoveries
FOR EACH ROW EXECUTE FUNCTION prevent_analytics_history_recovery_delete_098();

CREATE TRIGGER analytics_history_recoveries_truncate_guard_098
BEFORE TRUNCATE ON analytics_history_recoveries
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_history_recovery_truncate_098();

CREATE FUNCTION analytics_history_schedule_recovery_098(
    p_history_epoch uuid,
    p_reason text,
    p_at timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
    existing_id uuid;
    new_recovery_id uuid := gen_random_uuid();
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_reason IS NULL OR
       p_reason<>btrim(p_reason) OR char_length(p_reason) NOT BETWEEN 1 AND 128 OR
       p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'analytics history recovery schedule precondition failed' USING ERRCODE = 'P9803';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_history_epoch::text,98));
    SELECT recovery.recovery_id INTO existing_id FROM analytics_history_recoveries recovery
    WHERE recovery.history_epoch=p_history_epoch AND recovery.completed_at IS NULL FOR UPDATE;
    IF FOUND THEN
        RETURN existing_id;
    END IF;
    INSERT INTO analytics_history_recoveries(
        recovery_id,history_epoch,reason,scheduled_at,created_at,updated_at
    ) VALUES(new_recovery_id,p_history_epoch,p_reason,p_at,p_at,p_at);
    RETURN new_recovery_id;
END;
$$;

CREATE FUNCTION analytics_history_claim_recovery_098(
    p_history_epoch uuid,
    p_worker text,
    p_claim_token uuid,
    p_now timestamptz,
    p_lease_expires_at timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
    recovery analytics_history_recoveries%ROWTYPE;
BEGIN
    IF p_now IS NULL OR p_lease_expires_at IS NULL OR NOT isfinite(p_now) OR
       NOT isfinite(p_lease_expires_at) OR p_claim_token IS NULL OR
       p_claim_token='00000000-0000-0000-0000-000000000000'::uuid OR
       p_worker IS NULL OR p_worker<>btrim(p_worker) OR char_length(p_worker) NOT BETWEEN 1 AND 128 OR
       p_worker ~ '[[:cntrl:]]' OR p_lease_expires_at<=p_now THEN
        RAISE EXCEPTION 'analytics history recovery claim precondition failed' USING ERRCODE = 'P9803';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_history_epoch::text,98));
    SELECT * INTO recovery FROM analytics_history_recoveries
    WHERE history_epoch=p_history_epoch AND completed_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF recovery.claim_token IS NOT NULL AND recovery.lease_expires_at>p_now THEN
        RETURN NULL;
    END IF;
    IF p_now<recovery.scheduled_at OR p_now<recovery.updated_at THEN
        RAISE EXCEPTION 'analytics history recovery claim time regressed' USING ERRCODE = 'P9803';
    END IF;
    UPDATE analytics_history_recoveries
    SET claimed_by=p_worker,claim_token=p_claim_token,claimed_at=p_now,
        lease_expires_at=p_lease_expires_at,reconciled_at=NULL,updated_at=p_now
    WHERE recovery_id=recovery.recovery_id;
    RETURN recovery.recovery_id;
END;
$$;

CREATE FUNCTION analytics_history_reconcile_recovery_098(
    p_recovery_id uuid,
    p_claim_token uuid,
    p_consumer_floor numeric,
    p_stream_floor numeric,
    p_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    recovery analytics_history_recoveries%ROWTYPE;
    generation analytics_history_streams%ROWTYPE;
    changed boolean;
BEGIN
    IF p_claim_token IS NULL OR p_claim_token='00000000-0000-0000-0000-000000000000'::uuid OR
       p_at IS NULL OR NOT isfinite(p_at) OR
       p_consumer_floor IS NULL OR p_consumer_floor NOT BETWEEN 0 AND 18446744073709551615 OR
       p_stream_floor IS NULL OR p_stream_floor NOT BETWEEN 0 AND 18446744073709551615 THEN
        RAISE EXCEPTION 'analytics history recovery reconciliation precondition failed' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO recovery FROM analytics_history_recoveries
    WHERE recovery_id=p_recovery_id FOR UPDATE;
    IF NOT FOUND OR recovery.completed_at IS NOT NULL OR recovery.claim_token IS DISTINCT FROM p_claim_token OR
       recovery.lease_expires_at<=p_at OR p_at<recovery.claimed_at THEN
        RAISE EXCEPTION 'analytics history recovery claim was fenced' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO generation FROM analytics_history_streams
    WHERE history_epoch=recovery.history_epoch FOR UPDATE;
    IF NOT FOUND OR generation.retired_at IS NOT NULL OR
       p_stream_floor<generation.history_start_sequence-1 OR
       p_consumer_floor<generation.broker_consumer_ack_floor OR
       p_stream_floor<generation.broker_stream_ack_floor OR p_at<=generation.updated_at THEN
        RAISE EXCEPTION 'analytics history recovery floor precondition failed' USING ERRCODE = 'P9803';
    END IF;
    changed := p_consumer_floor<>generation.broker_consumer_ack_floor OR
        p_stream_floor<>generation.broker_stream_ack_floor;
    IF changed THEN
        UPDATE analytics_history_streams
        SET broker_consumer_ack_floor=p_consumer_floor,
            broker_stream_ack_floor=p_stream_floor,
            revision=revision+1,
            last_reconciled_at=GREATEST(last_reconciled_at,p_at),
            updated_at=p_at
        WHERE history_epoch=generation.history_epoch;
    END IF;
    UPDATE analytics_history_recoveries
    SET reconciled_at=p_at,updated_at=GREATEST(updated_at,p_at)
    WHERE recovery_id=p_recovery_id;
END;
$$;

CREATE FUNCTION analytics_history_complete_recovery_098(
    p_recovery_id uuid,
    p_claim_token uuid,
    p_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    recovery analytics_history_recoveries%ROWTYPE;
BEGIN
    IF p_claim_token IS NULL OR p_claim_token='00000000-0000-0000-0000-000000000000'::uuid OR
       p_at IS NULL OR NOT isfinite(p_at) THEN
        RAISE EXCEPTION 'analytics history recovery completion precondition failed' USING ERRCODE = 'P9803';
    END IF;
    SELECT * INTO recovery FROM analytics_history_recoveries
    WHERE recovery_id=p_recovery_id FOR UPDATE;
    IF NOT FOUND OR recovery.completed_at IS NOT NULL OR recovery.claim_token IS DISTINCT FROM p_claim_token OR
       recovery.reconciled_at IS NULL OR recovery.lease_expires_at<=p_at OR p_at<recovery.claimed_at THEN
        RAISE EXCEPTION 'analytics history recovery completion was fenced' USING ERRCODE = 'P9803';
    END IF;
    UPDATE analytics_history_recoveries
    SET completed_at=p_at,claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
        lease_expires_at=NULL,updated_at=p_at
    WHERE recovery_id=p_recovery_id;
END;
$$;

REVOKE ALL ON analytics_ingest_receipts,analytics_history_recoveries FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_ingest_receipt_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_ingest_receipt_delete_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_ingest_receipt_truncate_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_history_recovery_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_history_recovery_delete_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_history_recovery_truncate_098() FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_history_schedule_recovery_098(uuid,text,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_history_claim_recovery_098(uuid,text,uuid,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION analytics_history_complete_recovery_098(uuid,uuid,timestamptz) FROM PUBLIC;
