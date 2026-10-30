LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_246$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 245 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=245
          AND checksum_sha256='870b9b514ac812496d96c1b09fd3c0957079c53d101aa94d4de42352ed544bc6'
          AND down_checksum_sha256='b77e5ef9652bb7e4ac2653712025ece9f5977efec9e22b579363f766ed9f4528'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 246 requires verified 245' USING ERRCODE='P2460';
    END IF;
END;
$migration_246$;

CREATE OR REPLACE FUNCTION analytics_ingest_mark_prepared_098(
    p_history_epoch uuid, p_stream_sequence numeric,
    p_receipt_identity_sha256 bytea, p_at timestamptz
)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    receipt analytics_ingest_receipts%ROWTYPE;
    generation analytics_history_streams%ROWTYPE;
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_receipt_identity_sha256 IS NULL OR
       octet_length(p_receipt_identity_sha256)<>32 THEN
        RAISE EXCEPTION 'analytics ingest preparation precondition failed' USING ERRCODE='P9803';
    END IF;
    SELECT * INTO generation FROM analytics_history_streams WHERE history_epoch=p_history_epoch FOR UPDATE;
    IF NOT FOUND OR generation.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'analytics ingest history generation is unavailable' USING ERRCODE='P9803';
    END IF;
    SELECT * INTO receipt FROM analytics_ingest_receipts
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence FOR UPDATE;
    IF NOT FOUND OR receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256 THEN
        RAISE EXCEPTION 'analytics ingest receipt identity does not match' USING ERRCODE='P9803';
    END IF;
    IF receipt.state IN ('prepared','broker_ack_observed') THEN RETURN; END IF;
    -- Reconciled broker progress includes durably isolated terminal records.
    -- It cannot cover an unacknowledged gap or authorize skipping pending input.
    IF receipt.state<>'received' OR
       p_stream_sequence<>GREATEST(generation.prepared_stream_floor,generation.broker_stream_ack_floor)+1 OR
       p_at<=generation.updated_at THEN
        RAISE EXCEPTION 'analytics ingest preparation sequence is not contiguous' USING ERRCODE='P9803';
    END IF;
    UPDATE analytics_ingest_receipts SET state='prepared',prepared_at=p_at,updated_at=p_at
    WHERE history_epoch=p_history_epoch AND stream_sequence=p_stream_sequence;
    UPDATE analytics_history_streams SET prepared_stream_floor=p_stream_sequence,
        revision=revision+1,last_reconciled_at=GREATEST(last_reconciled_at,p_at),updated_at=p_at
    WHERE history_epoch=p_history_epoch;
END;
$$;
