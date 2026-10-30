LOCK TABLE schema_migrations, site_origin_route_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_485_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 484 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 484 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=484 AND
        migration_id='484_escalate_reseller_policies' AND
        checksum_sha256='447d48e465ee270bfe13ff03fda8fe38012fbab255c2d2891f8d8ab92070717f' AND
        down_checksum_sha256='c5e0b5c384938132bd631a96aa050d68bb9935e6f07aa8b68337670de68ec6c7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='site_origin_route_endpoints' AND column_name='host' AND data_type='inet') THEN
        RAISE EXCEPTION 'migration 485 requires the exact verified 484 release head' USING ERRCODE='P4850';
    END IF;
END;
$migration_485_up$;

-- 485（r136 p0c-origin-host，Codex 审测 A15/ORIGIN-DB-01；BATCH 预留 control 488，合入时按集成头改号并重钉前驱）。
-- 条件回源端点的 host 与普通回源（site_origins.host text）同一契约：规范 IP 或规范 DNS 域名。
-- 109 把列建成 inet，服务层已接受的域名在 INSERT 时报 22P02，PUT 返回 500。1.0.35 是初始版本（10-24 用户定不考虑兼容），
-- 直接改列类型；存量 inet 用 host() 转成不带掩码的文本，原有 IP 排除范围原样保留在新 CHECK 里。
--
-- 错误码：P4850 前驱不符；P4851 down 前驱不符；P4852 down 时存在域名端点（inet 放不下，拒绝而不是丢数据）。

-- 规范主机：全部小写、无首尾空白；IP 必须是规范写法的单个地址（无掩码、无 zone），且不是未指定/广播/链路本地/组播/IPv4 映射地址；
-- 其余按 DNS 域名：总长 1–253、至少两段、每段 1–63 的 [a-z0-9-] 且不以 - 开头结尾、末段含字母，排除 localhost 与反解域。
-- 与 site.normalizeConditionalOriginHost（Go）一致，Go 先规范化，这里是最后一道。
CREATE FUNCTION site_origin_route_host_valid_485(candidate text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    address inet;
BEGIN
    IF candidate <> lower(candidate) OR candidate <> btrim(candidate) OR char_length(candidate) NOT BETWEEN 1 AND 253 THEN
        RETURN false;
    END IF;
    IF pg_input_is_valid(candidate, 'inet') THEN
        address := candidate::inet;
        -- host() 是规范写法且不带掩码：'10.0.0.0/8'、'2001:0db8::1' 这类非规范值不等于自身的 host()。
        RETURN host(address) = candidate
           AND address <> '0.0.0.0'::inet AND address <> '::'::inet AND address <> '255.255.255.255'::inet
           AND NOT address << '169.254.0.0/16'::inet AND NOT address << 'fe80::/10'::inet
           AND NOT address << '224.0.0.0/4'::inet AND NOT address << 'ff00::/8'::inet
           AND NOT address << '::ffff:0.0.0.0/96'::inet;
    END IF;
    RETURN candidate ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
       AND split_part(candidate, '.', -1) ~ '[a-z]'
       AND candidate <> 'localhost'
       AND candidate !~ '[.](in-addr|ip6)[.]arpa$';
END;
$$;

ALTER TABLE site_origin_route_endpoints
    DROP CONSTRAINT site_origin_route_endpoints_host_check,
    ALTER COLUMN host TYPE text USING host(host),
    ADD CONSTRAINT site_origin_route_endpoints_host_check CHECK (site_origin_route_host_valid_485(host));
