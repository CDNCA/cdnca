-- 628 down：补发命令是事实，已有补发行时拒绝（回到唯一 (publication_id,node_id,site_id) 装不下它们）。
LOCK TABLE schema_migrations, firewall_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_628_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 628 OR
       (SELECT max(version) FROM schema_migrations) <> 628 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=628 AND
        migration_id='628_global_firewall_redelivery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 628 down requires the exact verified migration head' USING ERRCODE='P6282';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_command_outbox WHERE delivery>0) THEN
        RAISE EXCEPTION 'migration 628 down would orphan global firewall redelivery commands' USING ERRCODE='P6283';
    END IF;
END;
$migration_628_down$;

DROP TRIGGER firewall_command_outbox_delivery_628 ON firewall_command_outbox;
DROP FUNCTION protect_firewall_command_outbox_delivery_628();
DROP INDEX firewall_command_outbox_redelivery_628_idx;
ALTER TABLE firewall_command_outbox
    DROP CONSTRAINT firewall_command_outbox_publication_node_site_delivery_628_key,
    DROP CONSTRAINT firewall_command_outbox_delivery_628_check,
    DROP COLUMN delivery,
    ADD CONSTRAINT firewall_command_outbox_publication_node_site_key UNIQUE(publication_id,node_id,site_id);
