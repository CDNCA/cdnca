-- 611 回退：恢复 12 个 (tenant_scope_id, 操作人)→memberships 外键（约束名与 033/043/078/233/254 原名一致）。
-- 平台管理员（非该 scope 成员）留下的操作人记录都是只追加事实，回滚后旧外键容不下：拒绝回滚。
LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, node_scheduling_write_requests,
    announcements, announcement_versions, announcement_write_requests, package_monitor_policy_versions,
    announcement_archive_254, announcement_lifecycle_facts_254
    IN ACCESS EXCLUSIVE MODE;

DO $migration_611_down$
DECLARE
    target record;
    orphan boolean;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 611 OR
       (SELECT max(version) FROM schema_migrations) <> 611 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=611 AND
        migration_id='611_operator_user_foreign_keys' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 611 down requires the exact verified migration head' USING ERRCODE='P6111';
    END IF;
    FOR target IN SELECT * FROM (VALUES
        ('node_line_groups', 'created_by_user_id'), ('node_line_groups', 'updated_by_user_id'),
        ('node_line_groups', 'deleted_by_user_id'), ('node_line_group_revisions', 'created_by_user_id'),
        ('node_scheduling_write_requests', 'actor_user_id'), ('announcements', 'created_by_user_id'),
        ('announcement_versions', 'created_by_user_id'), ('announcement_write_requests', 'actor_user_id'),
        ('package_monitor_policy_versions', 'created_by_user_id'),
        ('announcement_archive_254', 'changed_by_user_id'), ('announcement_archive_254', 'archived_by_user_id'),
        ('announcement_lifecycle_facts_254', 'actor_user_id')) AS t(table_name, column_name)
    LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I fact WHERE fact.%I IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.%I))',
            target.table_name, target.column_name, target.column_name) INTO orphan;
        IF orphan THEN
            RAISE EXCEPTION 'migration 611 rollback would drop platform administrator operator facts in %.%',
                target.table_name, target.column_name USING ERRCODE='P6112';
        END IF;
    END LOOP;
END;
$migration_611_down$;

DROP TRIGGER announcement_lifecycle_facts_254_operator_611 ON announcement_lifecycle_facts_254;
ALTER TABLE announcement_lifecycle_facts_254
    DROP CONSTRAINT announcement_lifecycle_facts_254_actor_user_fk_611,
    ADD CONSTRAINT announcement_lifecycle_facts__tenant_scope_id_actor_user_i_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER announcement_archive_254_operator_611 ON announcement_archive_254;
ALTER TABLE announcement_archive_254
    DROP CONSTRAINT announcement_archive_254_changed_by_user_fk_611,
    DROP CONSTRAINT announcement_archive_254_archived_by_user_fk_611,
    ADD CONSTRAINT announcement_archive_254_tenant_scope_id_changed_by_user_i_fkey
        FOREIGN KEY (tenant_scope_id, changed_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT announcement_archive_254_tenant_scope_id_archived_by_user__fkey
        FOREIGN KEY (tenant_scope_id, archived_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER package_monitor_policy_versions_operator_611 ON package_monitor_policy_versions;
ALTER TABLE package_monitor_policy_versions
    DROP CONSTRAINT package_monitor_policy_versions_created_by_user_fk_611,
    ADD CONSTRAINT package_monitor_policy_versio_tenant_scope_id_created_by_u_fkey
        FOREIGN KEY (tenant_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER announcement_write_requests_operator_611 ON announcement_write_requests;
ALTER TABLE announcement_write_requests
    DROP CONSTRAINT announcement_write_requests_actor_user_fk_611,
    ADD CONSTRAINT announcement_write_requests_tenant_scope_id_actor_user_id_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER announcement_versions_operator_611 ON announcement_versions;
ALTER TABLE announcement_versions
    DROP CONSTRAINT announcement_versions_created_by_user_fk_611,
    ADD CONSTRAINT announcement_versions_tenant_scope_id_created_by_user_id_fkey
        FOREIGN KEY (tenant_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER announcements_operator_611 ON announcements;
ALTER TABLE announcements
    DROP CONSTRAINT announcements_created_by_user_fk_611,
    ADD CONSTRAINT announcements_tenant_scope_id_created_by_user_id_fkey
        FOREIGN KEY (tenant_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER node_scheduling_write_requests_operator_611 ON node_scheduling_write_requests;
ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_actor_user_fk_611,
    ADD CONSTRAINT node_scheduling_write_request_tenant_scope_id_actor_user_i_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER node_line_group_revisions_operator_611 ON node_line_group_revisions;
ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_created_by_user_fk_611,
    ADD CONSTRAINT node_line_group_revisions_tenant_scope_id_created_by_user__fkey
        FOREIGN KEY (tenant_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP TRIGGER node_line_groups_operator_611 ON node_line_groups;
ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_created_by_user_fk_611,
    DROP CONSTRAINT node_line_groups_updated_by_user_fk_611,
    DROP CONSTRAINT node_line_groups_deleted_by_user_fk_611,
    ADD CONSTRAINT node_line_groups_tenant_scope_id_created_by_user_id_fkey
        FOREIGN KEY (tenant_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_line_groups_tenant_scope_id_updated_by_user_id_fkey
        FOREIGN KEY (tenant_scope_id, updated_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_line_groups_deleted_actor_233_fk
        FOREIGN KEY (tenant_scope_id, deleted_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP FUNCTION control_operator_on_scope_611();
