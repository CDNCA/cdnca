-- 562 回滚：删掉“解除并加白”与单条解除持久化表；节点在下一次快照里不再收到 release 白名单（ACL 放行规则照常下发）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_562_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 562 OR
       (SELECT max(version) FROM schema_migrations) <> 562 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=562 AND
        migration_id='562_autodefense_site_allows' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 562 down requires the exact verified migration head' USING ERRCODE='P5621';
    END IF;
END;
$migration_562_down$;

DELETE FROM autodefense_report_receipts WHERE kind='release_acks';
ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift', 'waf_evidence'));

DROP TABLE autodefense_site_release_acks;
DROP TABLE autodefense_site_releases;
DROP TABLE autodefense_site_allows;
