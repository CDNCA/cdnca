LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    -- P1070 remains fail-closed until the 107 release digest and the 106 predecessor are frozen.
    RAISE EXCEPTION 'migration 107 rollback requires the exact verified 107 head; release checksum is not frozen'
        USING ERRCODE='P1070';
END;
$$;

LOCK TABLE schema_migrations, analytics_ingest_watermark_decisions_107,
    analytics_ingest_watermarks_107 IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM analytics_ingest_watermark_decisions_107) OR
       EXISTS (SELECT 1 FROM analytics_ingest_watermarks_107) THEN
        RAISE EXCEPTION 'migration 107 rollback would discard analytics watermark decisions or watermark state'
            USING ERRCODE='P1071';
    END IF;
END;
$$;

DROP TRIGGER analytics_ingest_watermark_decisions_truncate_guard_107
    ON analytics_ingest_watermark_decisions_107;
DROP TRIGGER analytics_ingest_watermarks_truncate_guard_107
    ON analytics_ingest_watermarks_107;
DROP TRIGGER analytics_ingest_watermark_decisions_guard_107
    ON analytics_ingest_watermark_decisions_107;
DROP TRIGGER analytics_ingest_watermarks_append_only_107
    ON analytics_ingest_watermarks_107;

DROP FUNCTION analytics_ingest_commit_watermark_107(
    uuid,text,text,uuid,text,text,bytea,bytea,numeric,timestamptz,interval,text,timestamptz
);
DROP FUNCTION analytics_history_generation_digest_107(
    text,text,text,text,numeric,numeric,uuid,numeric,timestamptz,text,timestamptz,bytea
);
DROP FUNCTION prevent_analytics_ingest_watermark_decision_truncate_107();
DROP FUNCTION prevent_analytics_ingest_watermark_truncate_107();
DROP FUNCTION guard_analytics_ingest_watermark_decision_107();
DROP FUNCTION guard_analytics_ingest_watermark_107();

DROP TABLE analytics_ingest_watermark_decisions_107;
DROP TABLE analytics_ingest_watermarks_107;
