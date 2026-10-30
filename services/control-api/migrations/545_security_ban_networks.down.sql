-- 545 回滚：恢复 408 的单地址约束。已有网段封禁行（含已解封、已到期的历史）是审计过的安全记录，
-- 回滚会丢掉谁封了哪个网段，按 408 down 的做法拒绝回滚，不删行。
LOCK TABLE schema_migrations, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_545_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 545 OR
       (SELECT max(version) FROM schema_migrations) <> 545 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=545 AND
        migration_id='545_security_ban_networks' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 545 down requires the exact verified migration head' USING ERRCODE='P5451';
    END IF;
    IF EXISTS (SELECT 1 FROM security_ban_entries
               WHERE masklen(client_ip) <> CASE WHEN family(client_ip)=4 THEN 32 ELSE 128 END) THEN
        RAISE EXCEPTION 'migration 545 rollback would discard network bans of the security ban list' USING ERRCODE='P5452';
    END IF;
END;
$migration_545_down$;

ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_client_ip_545;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_client_ip_check
    CHECK (masklen(client_ip) = CASE WHEN family(client_ip)=4 THEN 32 ELSE 128 END);
