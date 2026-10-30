-- 489（r136 pf09-ticket，PF09 / 用户 10-24 23:5x Q2；派单号 489，本地守卫指当前集成头 484，合入时按连号改号并重钉前驱）。
LOCK TABLE schema_migrations, installation_ban_node_state IN ACCESS EXCLUSIVE MODE;

DO $migration_489_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 488 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 488 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=488 AND
        migration_id='488_market_renewal_stop_notices' AND
        checksum_sha256='9065189ac08869cc500223bfaf1458c6c9c994e21bf5ed1c3f8f129dfdb43692' AND
        down_checksum_sha256='81a076a6a4843d9b7caaee976d631f24da10240587948cacb9d21cc50b863a7e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.installation_ban_node_state') IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='installation_ban_node_state' AND column_name IN ('ticket_issued_at', 'ticket_not_after')) THEN
        RAISE EXCEPTION 'migration 489 requires the exact verified 488 release head' USING ERRCODE='P4890';
    END IF;
END;
$migration_489_up$;

-- 每个节点最后一次回执里它持有的签名凭据（ServiceTicket）签发时间与到期时间：主控节点页据此显示
-- "最后凭据时间"和"剩余天数"。两列同为空 = 节点还没拿到首张凭据（不对外开放）。
-- 已有行保持 NULL，节点下一次回执即补上。
ALTER TABLE installation_ban_node_state
    ADD COLUMN ticket_issued_at timestamptz,
    ADD COLUMN ticket_not_after timestamptz,
    ADD CONSTRAINT installation_ban_node_state_ticket_489_check CHECK (
        (ticket_issued_at IS NULL) = (ticket_not_after IS NULL) AND
        (ticket_not_after IS NULL OR ticket_not_after > ticket_issued_at));
