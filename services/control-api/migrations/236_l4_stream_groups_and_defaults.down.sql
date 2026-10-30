LOCK TABLE schema_migrations, access_scopes, l4_forwards, l4_stream_groups,
    l4_stream_group_members, l4_stream_user_defaults,
    l4_stream_group_default_write_requests, l4_stream_group_display_id_sequences,
    l4_stream_user_default_display_id_sequences
IN ACCESS EXCLUSIVE MODE;

DO $migration_236_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 236 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 236 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 236 AND migration_id = '236_l4_stream_groups_and_defaults' AND
              checksum_sha256 = 'cd3ae7c94469bcc37595e8169ff431ef7e46580ee3369bc127ee2305f751f65f' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_groups') IS NULL OR
            to_regclass(current_schema() || '.l4_stream_group_members') IS NULL OR
            to_regclass(current_schema() || '.l4_stream_user_defaults') IS NULL OR
            to_regclass(current_schema() || '.l4_stream_group_default_write_requests') IS NULL OR
            to_regprocedure(current_schema() || '.allocate_l4_stream_group_display_id_236()') IS NULL OR
            to_regprocedure(current_schema() || '.allocate_l4_stream_user_default_display_id_236()') IS NULL OR
            to_regprocedure(current_schema() || '.protect_l4_stream_group_236()') IS NULL OR
            to_regprocedure(current_schema() || '.protect_l4_stream_group_write_request_236()') IS NULL OR
            NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = 'l4_forwards' AND
                      column_name = 'balance_way'
            ) THEN
        RAISE EXCEPTION 'migration 236 rollback requires the exact verified 236 release head'
            USING ERRCODE = 'P2363';
    END IF;
    -- balance_way 一旦被默认值带入或批量修改改过，回滚会静默丢弃该意图，故此处拒绝回滚。
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE balance_way <> 'rr') OR
       EXISTS (SELECT 1 FROM l4_stream_groups) OR
       EXISTS (SELECT 1 FROM l4_stream_group_members) OR
       EXISTS (SELECT 1 FROM l4_stream_user_defaults) OR
       EXISTS (SELECT 1 FROM l4_stream_group_default_write_requests) OR
       EXISTS (SELECT 1 FROM l4_stream_user_default_display_id_sequences WHERE next_value > 1) THEN
        RAISE EXCEPTION 'migration 236 rollback cannot discard stream groups, defaults, or idempotency receipts'
            USING ERRCODE = 'P2363';
    END IF;
END;
$migration_236_down$;

DO $l4_stream_group_runtime_revokes$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE SELECT, INSERT, UPDATE ON l4_stream_group_display_id_sequences FROM cdnca_control_app;
        REVOKE SELECT, INSERT, UPDATE ON l4_stream_user_default_display_id_sequences FROM cdnca_control_app;
        REVOKE SELECT, INSERT, UPDATE ON l4_stream_group_default_write_requests FROM cdnca_control_app;
        REVOKE SELECT, INSERT, DELETE ON l4_stream_user_defaults FROM cdnca_control_app;
        REVOKE SELECT, INSERT, DELETE ON l4_stream_group_members FROM cdnca_control_app;
        REVOKE SELECT, INSERT, UPDATE, DELETE ON l4_stream_groups FROM cdnca_control_app;
    END IF;
END;
$l4_stream_group_runtime_revokes$;

DROP TRIGGER l4_stream_group_default_write_requests_truncate_236 ON l4_stream_group_default_write_requests;
DROP TRIGGER l4_stream_group_default_write_requests_immutable_236 ON l4_stream_group_default_write_requests;
DROP FUNCTION protect_l4_stream_group_write_request_236();

DROP TRIGGER l4_stream_groups_truncate_236 ON l4_stream_groups;
DROP TRIGGER l4_stream_groups_delete_236 ON l4_stream_groups;
DROP TRIGGER l4_stream_groups_update_236 ON l4_stream_groups;
DROP TRIGGER l4_stream_user_defaults_display_id_236 ON l4_stream_user_defaults;
DROP FUNCTION allocate_l4_stream_user_default_display_id_236();

DROP TRIGGER l4_stream_groups_display_id_236 ON l4_stream_groups;
DROP FUNCTION protect_l4_stream_group_236();
DROP FUNCTION allocate_l4_stream_group_display_id_236();

DROP TABLE l4_stream_group_display_id_sequences;
DROP TABLE l4_stream_user_default_display_id_sequences;
DROP TABLE l4_stream_group_default_write_requests;

DROP INDEX l4_stream_user_defaults_scope_created_236_idx;
DROP INDEX l4_stream_user_defaults_group_236_idx;
DROP INDEX l4_stream_user_defaults_global_236_idx;
DROP TABLE l4_stream_user_defaults;

DROP INDEX l4_stream_group_members_scope_236_idx;
DROP INDEX l4_stream_group_members_stream_236_idx;
DROP TABLE l4_stream_group_members;

DROP INDEX l4_stream_groups_owner_created_active_236_idx;
DROP INDEX l4_stream_groups_scope_created_active_236_idx;
DROP INDEX l4_stream_groups_scope_name_lower_active_236_idx;
DROP TABLE l4_stream_groups;

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_balance_way_236_check,
    DROP COLUMN balance_way;
