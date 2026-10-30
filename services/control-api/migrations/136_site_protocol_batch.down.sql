-- migration 136 rollback requires the exact verified 136 head
LOCK TABLE schema_migrations, site_protocol_batches, site_protocol_states,
    site_protocol_batch_items, site_protocol_jobs, site_protocol_node_results,
    site_protocol_write_requests, site_protocol_outbox, site_protocol_audit_events,
    permissions, role_permissions, custom_rbac_permission_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_136$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 136 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 136 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 136 AND migration_id = '136_site_protocol_batch' AND
              checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 135 AND migration_id = '135_user_groups' AND
              checksum_sha256 = 'cac03de016d85a2e4fbaf225b987e72cd72ecec406d3520adbc168b32097c121' AND
              down_checksum_sha256 = '33cb1ca76ea840e4f83842775435d0ebc3dace58b38d0a9a10706a46ba669c78' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 136 rollback requires the exact verified 136 head'
            USING ERRCODE = 'P1360';
    END IF;
END;
$migration_136$;

DO $block$
BEGIN
    IF EXISTS(SELECT 1 FROM site_protocol_batches LIMIT 1) OR
       EXISTS(SELECT 1 FROM site_protocol_states LIMIT 1) OR
       EXISTS(SELECT 1 FROM site_protocol_write_requests LIMIT 1) OR
       EXISTS(SELECT 1 FROM site_protocol_audit_events LIMIT 1) THEN
        RAISE EXCEPTION 'migration 136 rollback would discard site protocol facts' USING ERRCODE='P1366';
    END IF;
END;
$block$;

DROP TRIGGER site_protocol_audit_truncate_136 ON site_protocol_audit_events;
DROP TRIGGER site_protocol_audit_guard_136 ON site_protocol_audit_events;
DROP FUNCTION guard_site_protocol_append_only_136();
DROP TRIGGER site_protocol_receipts_guard_136 ON site_protocol_write_requests;
DROP FUNCTION guard_site_protocol_receipt_136();
DROP TRIGGER site_protocol_outbox_guard_136 ON site_protocol_outbox;
DROP FUNCTION guard_site_protocol_outbox_136();
DROP TRIGGER site_protocol_node_results_guard_136 ON site_protocol_node_results;
DROP FUNCTION guard_site_protocol_node_result_136();
DROP TRIGGER site_protocol_items_guard_136 ON site_protocol_batch_items;
DROP FUNCTION guard_site_protocol_item_136();
DROP TRIGGER site_protocol_states_guard_136 ON site_protocol_states;
DROP FUNCTION guard_site_protocol_state_136();
DROP TRIGGER site_protocol_batches_guard_136 ON site_protocol_batches;
DROP FUNCTION guard_site_protocol_batch_136();
DROP TRIGGER site_protocol_items_scope_136 ON site_protocol_batch_items;
DROP TRIGGER site_protocol_node_results_scope_136 ON site_protocol_node_results;
DROP TRIGGER site_protocol_states_scope_136 ON site_protocol_states;
DROP TRIGGER site_protocol_batches_scope_136 ON site_protocol_batches;
DROP FUNCTION validate_site_protocol_scope_136();

DROP TABLE site_protocol_audit_events;
DROP TABLE site_protocol_outbox;
DROP TABLE site_protocol_write_requests;
DROP TABLE site_protocol_node_results;
DROP TABLE site_protocol_jobs;
DROP TABLE site_protocol_states;
DROP TABLE site_protocol_batch_items;
DROP TABLE site_protocol_batches;

DROP TRIGGER roles_site_protocol_permissions_136 ON roles;
DROP FUNCTION grant_site_protocol_permissions_136();
DELETE FROM role_permissions WHERE permission_name IN ('site_protocols.read','site_protocols.manage');
DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('site_protocols.read','site_protocols.manage');
DELETE FROM permissions WHERE name IN ('site_protocols.read','site_protocols.manage');
