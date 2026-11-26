LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

-- 704 回退：只删除本迁移插入的 .en-us 模板（notification_templates_seed_704 登记的行）与 users.locale，
-- 运营自建的 .en-us 模板保留；已经用本迁移英文模板入队的通知存在时拒绝回退。
DO $migration_704_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 704 OR
       (SELECT max(version) FROM schema_migrations) <> 704 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=704 AND
        migration_id='704_notification_templates_en' AND integrity_state='verified' AND
        metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM notification_outbox outbox JOIN notification_templates_seed_704 seed
         ON seed.template_id = outbox.template_id AND seed.version = outbox.template_version
        AND seed.channel = outbox.channel) THEN
        RAISE EXCEPTION 'migration 704 rollback requires the exact unused verified release head' USING ERRCODE='P7041';
    END IF;
END;
$migration_704_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates template USING notification_templates_seed_704 seed
WHERE template.template_id = seed.template_id AND template.version = seed.version AND template.channel = seed.channel;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

DROP TABLE notification_templates_seed_704;
ALTER TABLE users DROP COLUMN locale;
