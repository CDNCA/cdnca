LOCK TABLE schema_migrations,analytics_history_streams,analytics_access_source_window_contributions_208
IN ACCESS EXCLUSIVE MODE;

DO $migration_208_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>208 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>208 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=208 AND migration_id='208_analytics_access_source_window_contributions' AND
              checksum_sha256='b7a561576842b5010958fe91fc16d2795ecb38f6720386d53bcfa8e9063001c8' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=207 AND migration_id='207_account_order_records' AND
              checksum_sha256='9430b75c0e43cac163fc3dc3d16dcba4294f67f91237f2d473a91aa1fc3ef6cb' AND
              down_checksum_sha256='88d49bc7e2421b8b8e135d19aa66d666ca10808d8e87d1ba22615880ea02b34f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 208 rollback requires the exact verified 208 and 207 release heads'
            USING ERRCODE='P2080';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_access_source_window_contributions_208) THEN
        RAISE EXCEPTION 'migration 208 rollback would discard access source window contributions'
            USING ERRCODE='P2082';
    END IF;
END;
$migration_208_down$;

DROP TRIGGER analytics_access_source_window_contributions_208_no_truncate
    ON analytics_access_source_window_contributions_208;
DROP TRIGGER analytics_access_source_window_contributions_208_immutable
    ON analytics_access_source_window_contributions_208;
DROP TABLE analytics_access_source_window_contributions_208;
ALTER TABLE analytics_history_streams
    DROP CONSTRAINT analytics_history_streams_epoch_installation_208_key;
DROP FUNCTION reject_analytics_access_source_window_contribution_truncate_208();
DROP FUNCTION guard_analytics_access_source_window_contribution_208();
