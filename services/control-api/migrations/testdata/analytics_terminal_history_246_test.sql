\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE SCHEMA analytics_terminal_246_test;
SET LOCAL search_path=analytics_terminal_246_test,public;
CREATE TABLE schema_migrations AS SELECT * FROM public.schema_migrations WHERE version<=245;
CREATE TABLE analytics_history_streams (
    history_epoch uuid PRIMARY KEY, retired_at timestamptz,
    prepared_stream_floor numeric NOT NULL, broker_stream_ack_floor numeric NOT NULL,
    revision bigint NOT NULL, last_reconciled_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE analytics_ingest_receipts (
    history_epoch uuid NOT NULL, stream_sequence numeric NOT NULL,
    receipt_identity_sha256 bytea NOT NULL, state text NOT NULL,
    prepared_at timestamptz, updated_at timestamptz NOT NULL
);
INSERT INTO analytics_history_streams VALUES
('10000000-0000-4000-8000-000000000246',NULL,0,2,1,'2026-01-01','2026-01-01');
INSERT INTO analytics_ingest_receipts VALUES
('10000000-0000-4000-8000-000000000246',3,decode(repeat('ab',32),'hex'),'received',NULL,'2026-01-01');
INSERT INTO schema_migrations(version,checksum_sha256) VALUES
(246,'2237c5ed6ee0bcf0407dcb3b6ae299c93b3f3fe92c71c093779517ea435ee318');
\ir ../246_analytics_terminal_history_progress.down.sql
DELETE FROM schema_migrations WHERE version=246;
DO $$ BEGIN
    PERFORM analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',3,decode(repeat('ab',32),'hex'),'2026-01-02');
    RAISE EXCEPTION 'old preparation unexpectedly crossed isolated records';
EXCEPTION WHEN SQLSTATE 'P9803' THEN NULL; END $$;
\ir ../246_analytics_terminal_history_progress.up.sql
SELECT analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',3,decode(repeat('ab',32),'hex'),'2026-01-02');
SELECT analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',3,decode(repeat('ab',32),'hex'),'2026-01-03');
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM analytics_history_streams WHERE prepared_stream_floor=3 AND broker_stream_ack_floor=2 AND revision=2)
       OR NOT EXISTS (SELECT 1 FROM analytics_ingest_receipts WHERE state='prepared') THEN
        RAISE EXCEPTION 'terminal recovery progress or replay is incorrect';
    END IF;
END $$;
INSERT INTO analytics_ingest_receipts VALUES
('10000000-0000-4000-8000-000000000246',5,decode(repeat('cd',32),'hex'),'received',NULL,'2026-01-02');
DO $$ BEGIN
    PERFORM analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',5,decode(repeat('cd',32),'hex'),'2026-01-03');
    RAISE EXCEPTION 'unconfirmed sequence gap was accepted';
EXCEPTION WHEN SQLSTATE 'P9803' THEN NULL; END $$;
DO $$ BEGIN
    PERFORM analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',3,decode(repeat('ff',32),'hex'),'2026-01-03');
    RAISE EXCEPTION 'conflicting receipt digest was accepted';
EXCEPTION WHEN SQLSTATE 'P9803' THEN NULL; END $$;
INSERT INTO schema_migrations(version,checksum_sha256) VALUES
(246,'2237c5ed6ee0bcf0407dcb3b6ae299c93b3f3fe92c71c093779517ea435ee318');
\ir ../246_analytics_terminal_history_progress.down.sql
UPDATE analytics_history_streams SET prepared_stream_floor=0;
UPDATE analytics_ingest_receipts SET state='received' WHERE stream_sequence=3;
DO $$ BEGIN
    PERFORM analytics_ingest_mark_prepared_098('10000000-0000-4000-8000-000000000246',3,decode(repeat('ab',32),'hex'),'2026-01-03');
    RAISE EXCEPTION 'rollback did not restore previous behavior';
EXCEPTION WHEN SQLSTATE 'P9803' THEN NULL; END $$;
ROLLBACK;
SELECT 'TERMINAL_RECOVERY_SQL_ROUNDTRIP_OK';
