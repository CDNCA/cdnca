-- 569（fix-dnscert DNS-SEC-20261027-01，占位，合入时由主会话改号与改钉前驱；前驱暂钉集成头 552_usage_report_state）。
-- 平台 DNS 副本（节点管理 > DNS配置 同步到每个租户的 dns_providers 行）与租户本人提交的 DNS 账户持久区分：
-- managed_by='platform' 只供平台已分配的 CNAME 记录与平台管理员发起的操作使用；租户不能用它新增解析区、
-- 申请 DNS-01 证书、做建站自动添加记录，也不能编辑/删除/验证它（服务端与 worker 双层校验，见 internal/dnsacme、
-- acmeruntime、dnsproviderremotesource、site）。
-- 不回填：1.0.35 全新安装（台账 10-17 04:35 第 9 条）；平台同步每次运行都把副本标成 platform。
LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_569_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 568 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 568 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=568 AND
        migration_id='568_account_login_captcha_replay' AND
        checksum_sha256='dd0bd4387c83298b049f0853df143ca205971964254f9edad685587885f92cca' AND
        down_checksum_sha256='6a1b72a66a3297c3acb9b3f3f4a9f07f5cc96e50af3577c1b60a3a9de9dbefb0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='dns_providers' AND column_name='managed_by'
          AND table_schema=current_schema()
       ) THEN
        RAISE EXCEPTION 'migration 569 requires the exact verified 568 release head' USING ERRCODE='P5690';
    END IF;
END;
$migration_569_up$;

ALTER TABLE dns_providers
    ADD COLUMN managed_by text NOT NULL DEFAULT 'tenant' CHECK (managed_by IN ('tenant', 'platform'));
