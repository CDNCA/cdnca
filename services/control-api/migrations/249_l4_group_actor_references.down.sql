LOCK TABLE schema_migrations,l4_stream_groups,l4_stream_user_defaults,memberships IN ACCESS EXCLUSIVE MODE;
DO $migration_249_down$ BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 249 OR
       EXISTS(SELECT 1 FROM l4_stream_groups g
           WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=g.scope_id AND m.user_id=g.created_by_user_id)
              OR NOT EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=g.scope_id AND m.user_id=g.updated_by_user_id)) OR
       EXISTS(SELECT 1 FROM l4_stream_user_defaults d
           WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=d.scope_id AND m.user_id=d.created_by_user_id)) THEN
        RAISE EXCEPTION 'retain cross-scope group and default actors during binary rollback' USING ERRCODE='P2491';
    END IF;
END $migration_249_down$;

ALTER TABLE l4_stream_groups
    DROP CONSTRAINT l4_stream_groups_created_by_user_249_fkey,
    DROP CONSTRAINT l4_stream_groups_updated_by_user_249_fkey,
    ADD CONSTRAINT l4_stream_groups_scope_id_created_by_user_id_fkey
        FOREIGN KEY (scope_id,created_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_stream_groups_scope_id_updated_by_user_id_fkey
        FOREIGN KEY (scope_id,updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT;
ALTER TABLE l4_stream_user_defaults
    DROP CONSTRAINT l4_stream_user_defaults_created_by_user_249_fkey,
    ADD CONSTRAINT l4_stream_user_defaults_scope_id_created_by_user_id_fkey
        FOREIGN KEY (scope_id,created_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT;
