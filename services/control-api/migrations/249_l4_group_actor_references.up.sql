LOCK TABLE schema_migrations,l4_stream_groups,l4_stream_user_defaults IN ACCESS EXCLUSIVE MODE;
DO $migration_249$ BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 248 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=248 AND integrity_state='verified'
        AND checksum_sha256='b8529c8891072609b5058003eabe00ca08386013801e9b36ef5e30df31a119a3'
        AND down_checksum_sha256='e1add59d1128952e6c0a0462fcfed3fa88ca68f349eb923b600f9859b8024909'
    ) THEN RAISE EXCEPTION 'migration 249 requires verified 248' USING ERRCODE='P2490'; END IF;
END $migration_249$;

-- Owners belong to the target scope; the real actor may be a platform administrator.
ALTER TABLE l4_stream_groups
    DROP CONSTRAINT l4_stream_groups_scope_id_created_by_user_id_fkey,
    DROP CONSTRAINT l4_stream_groups_scope_id_updated_by_user_id_fkey,
    ADD CONSTRAINT l4_stream_groups_created_by_user_249_fkey
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_stream_groups_updated_by_user_249_fkey
        FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE l4_stream_user_defaults
    DROP CONSTRAINT l4_stream_user_defaults_scope_id_created_by_user_id_fkey,
    ADD CONSTRAINT l4_stream_user_defaults_created_by_user_249_fkey
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
