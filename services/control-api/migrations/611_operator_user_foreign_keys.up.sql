-- 611（r136 omission-fix-b，COORD.md 11-01 登记 control 611，前驱 610_node_ssh_install_language）：
--   fix-adminall 补充②："(scope_id,user_id)→memberships 外键把操作人须为成员写死"，平台管理员不是租户成员时被拒（23503）。
--   与 531/534 同一做法：下列 12 个操作人外键 (tenant_scope_id, 操作人)→memberships 改为 操作人→users(id)；
--   "操作人须是该 scope 的成员（任意状态，与原外键同义）或平台管理员（control_platform_admin_435）"只由触发器保证。
--   033 node_line_groups(created/updated/deleted_by)、node_line_group_revisions(created_by)、node_scheduling_write_requests(actor)
--   043 announcements(created_by)、announcement_versions(created_by)、announcement_write_requests(actor)
--   078 package_monitor_policy_versions(created_by)
--   254 announcement_archive_254(changed_by/archived_by)、announcement_lifecycle_facts_254(actor)
--   收件人/受众/所有者类外键（announcement_audience_users、announcement_recipient_snapshots、
--   package_monitor_subscription_owners 等）是成员关系本身，不动。
LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, node_scheduling_write_requests,
    announcements, announcement_versions, announcement_write_requests, package_monitor_policy_versions,
    announcement_archive_254, announcement_lifecycle_facts_254
    IN ACCESS EXCLUSIVE MODE;

DO $migration_611_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 610 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 610 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=610 AND
        migration_id='610_node_ssh_install_language' AND
        checksum_sha256='2f7d56ed175e4ec1570078d68a437d303546fb0b10d6c269bbfa1e2502bb6224' AND
        down_checksum_sha256='cbc597d071c5c4742f3a865a01096708d2b950be77a26f5c3501acc44911a8be' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM pg_proc WHERE proname='control_operator_on_scope_611'
          AND pronamespace=current_schema()::regnamespace
       ) THEN
        RAISE EXCEPTION 'migration 611 requires the exact verified 610 release head' USING ERRCODE='P6110';
    END IF;
END;
$migration_611_up$;

-- TG_ARGV：操作人列名（可空列为 NULL 时跳过）。scope 列固定为 tenant_scope_id。
CREATE FUNCTION control_operator_on_scope_611()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_json jsonb := to_jsonb(NEW);
    old_json jsonb;
    column_name text;
    operator_id uuid;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        old_json := to_jsonb(OLD);
    END IF;
    FOREACH column_name IN ARRAY TG_ARGV LOOP
        operator_id := (row_json->>column_name)::uuid;
        CONTINUE WHEN operator_id IS NULL;
        -- UPDATE 只在操作人或 scope 变了时复核（与原外键只在引用列变化时检查同义）。
        CONTINUE WHEN TG_OP = 'UPDATE' AND operator_id IS NOT DISTINCT FROM (old_json->>column_name)::uuid
            AND NEW.tenant_scope_id IS NOT DISTINCT FROM OLD.tenant_scope_id;
        IF NOT EXISTS (
            SELECT 1 FROM memberships membership
            WHERE membership.scope_id = NEW.tenant_scope_id AND membership.user_id = operator_id
        ) AND NOT control_platform_admin_435(operator_id, NULL) THEN
            RAISE EXCEPTION '% % must be a member of the scope or a platform administrator', TG_TABLE_NAME, column_name
                USING ERRCODE = 'P6113';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_tenant_scope_id_created_by_user_id_fkey,
    DROP CONSTRAINT node_line_groups_tenant_scope_id_updated_by_user_id_fkey,
    DROP CONSTRAINT node_line_groups_deleted_actor_233_fk,
    ADD CONSTRAINT node_line_groups_created_by_user_fk_611
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_line_groups_updated_by_user_fk_611
        FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_line_groups_deleted_by_user_fk_611
        FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER node_line_groups_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, created_by_user_id, updated_by_user_id, deleted_by_user_id
    ON node_line_groups FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('created_by_user_id', 'updated_by_user_id', 'deleted_by_user_id');

ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_tenant_scope_id_created_by_user__fkey,
    ADD CONSTRAINT node_line_group_revisions_created_by_user_fk_611
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER node_line_group_revisions_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, created_by_user_id
    ON node_line_group_revisions FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('created_by_user_id');

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_request_tenant_scope_id_actor_user_i_fkey,
    ADD CONSTRAINT node_scheduling_write_requests_actor_user_fk_611
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER node_scheduling_write_requests_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, actor_user_id
    ON node_scheduling_write_requests FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('actor_user_id');

ALTER TABLE announcements
    DROP CONSTRAINT announcements_tenant_scope_id_created_by_user_id_fkey,
    ADD CONSTRAINT announcements_created_by_user_fk_611
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER announcements_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, created_by_user_id
    ON announcements FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('created_by_user_id');

ALTER TABLE announcement_versions
    DROP CONSTRAINT announcement_versions_tenant_scope_id_created_by_user_id_fkey,
    ADD CONSTRAINT announcement_versions_created_by_user_fk_611
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER announcement_versions_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, created_by_user_id
    ON announcement_versions FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('created_by_user_id');

ALTER TABLE announcement_write_requests
    DROP CONSTRAINT announcement_write_requests_tenant_scope_id_actor_user_id_fkey,
    ADD CONSTRAINT announcement_write_requests_actor_user_fk_611
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER announcement_write_requests_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, actor_user_id
    ON announcement_write_requests FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('actor_user_id');

ALTER TABLE package_monitor_policy_versions
    DROP CONSTRAINT package_monitor_policy_versio_tenant_scope_id_created_by_u_fkey,
    ADD CONSTRAINT package_monitor_policy_versions_created_by_user_fk_611
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER package_monitor_policy_versions_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, created_by_user_id
    ON package_monitor_policy_versions FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('created_by_user_id');

ALTER TABLE announcement_archive_254
    DROP CONSTRAINT announcement_archive_254_tenant_scope_id_changed_by_user_i_fkey,
    DROP CONSTRAINT announcement_archive_254_tenant_scope_id_archived_by_user__fkey,
    ADD CONSTRAINT announcement_archive_254_changed_by_user_fk_611
        FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT announcement_archive_254_archived_by_user_fk_611
        FOREIGN KEY (archived_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER announcement_archive_254_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, changed_by_user_id, archived_by_user_id
    ON announcement_archive_254 FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('changed_by_user_id', 'archived_by_user_id');

ALTER TABLE announcement_lifecycle_facts_254
    DROP CONSTRAINT announcement_lifecycle_facts__tenant_scope_id_actor_user_i_fkey,
    ADD CONSTRAINT announcement_lifecycle_facts_254_actor_user_fk_611
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
CREATE TRIGGER announcement_lifecycle_facts_254_operator_611
    BEFORE INSERT OR UPDATE OF tenant_scope_id, actor_user_id
    ON announcement_lifecycle_facts_254 FOR EACH ROW
    EXECUTE FUNCTION control_operator_on_scope_611('actor_user_id');
