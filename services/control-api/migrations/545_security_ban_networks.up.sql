-- 545（fix-cidrban，用户 10-27：封禁名单支持按网段封禁，如 /24）：security_ban_entries.client_ip
-- 由 408 的“只能是单地址”（masklen 32/128）放宽为单地址或网段：IPv4 /8–/32、IPv6 /32–/128，
-- 且必须是网络地址（主机位为 0，与 libs/edgeconfig/securityban CanonicalClient 规范化一致）。
-- 网段只下发给声明 CAPABILITY_NAME_BAN_CIDR（74）的节点，旧节点只收到单地址条目。
-- 前驱 544（official_rule_packs_enabled），守卫钉 544 校验和。
LOCK TABLE schema_migrations, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_545_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 544 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 544 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=544 AND
        migration_id='544_official_rule_packs_enabled' AND
        checksum_sha256='5ba1918d362a5a27025cfb318084d64de4472dc6340590d0ddc72ce96ac1a997' AND
        down_checksum_sha256='2e09f9793be4ddb97f8b37ca32793d11ccb41fa274146d73cf45349ca50b0ab8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 545 requires the exact verified 544 release head' USING ERRCODE='P5450';
    END IF;
END;
$migration_545_up$;

ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_client_ip_check;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_client_ip_545 CHECK (
    masklen(client_ip) BETWEEN CASE WHEN family(client_ip)=4 THEN 8 ELSE 32 END
                           AND CASE WHEN family(client_ip)=4 THEN 32 ELSE 128 END
    AND client_ip = network(client_ip));
