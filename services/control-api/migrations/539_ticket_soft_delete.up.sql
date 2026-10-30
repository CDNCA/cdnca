-- 539（fix-ticketops，用户 10-27 要求工单管理员可删除工单）：工单软删除。
-- 删除只打标记（deleted_at / deleted_by_user_id），消息与附件保留（314 规定已绑定附件
-- 永不删除）；已删除工单对客户、平台、代理商三端都不可见，附件也不再可下载。
-- 前驱 538（node_storage_republication），守卫钉 538 校验和。
LOCK TABLE schema_migrations, tickets IN ACCESS EXCLUSIVE MODE;

DO $migration_539_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 538 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 538 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=538 AND
        migration_id='538_node_storage_republication' AND
        checksum_sha256='c66c5d1f086777f9f5da89be7e4059c389a97e6df68ee9681f657b5c767a8617' AND
        down_checksum_sha256='2ad500fef470fd36c6219f6882fcf69b032eb8185bf896d2d20a25be6fa11fbb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='tickets' AND column_name='deleted_at'
       ) THEN
        RAISE EXCEPTION 'migration 539 requires the exact verified 538 release head' USING ERRCODE='P5390';
    END IF;
END;
$migration_539_up$;

ALTER TABLE tickets ADD COLUMN deleted_at timestamptz CHECK (deleted_at IS NULL OR isfinite(deleted_at));
ALTER TABLE tickets ADD COLUMN deleted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE tickets ADD CONSTRAINT tickets_deleted_by_539_check
    CHECK ((deleted_at IS NULL) = (deleted_by_user_id IS NULL));

-- 一经删除不可恢复、不可再改（运行时角色只有 UPDATE，没有 DELETE）。
CREATE FUNCTION tickets_deleted_guard_539()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted tickets cannot be changed' USING ERRCODE='P5393';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tickets_deleted_guard_539
BEFORE UPDATE ON tickets
FOR EACH ROW EXECUTE FUNCTION tickets_deleted_guard_539();
