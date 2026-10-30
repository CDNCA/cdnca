LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_425_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 424 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 424 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=424 AND
        migration_id='424_rule_intel_report_state' AND
        checksum_sha256='95bbc6c2d73c3fc2731dbf024615dcc0e350013081c05e502c771c5b04ec2f12' AND
        down_checksum_sha256='6251b5b4389516bb7e69b90047c6c4038463f2457bf52a242a111807ce018025' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.waf_adapt_cookies') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 425 requires the exact verified 424 release head' USING ERRCODE='P4250';
    END IF;
END;
$migration_425_up$;

-- 425（r136 ri-wire，占位号：合入时由主会话统一改号）。站点 Cookie 名集合
-- （ADR 0011 §3.3、契约 §3.6 cookie_names/cookie_mature）：节点每小时在 waf_evidence
-- 里报干净样本中的 Cookie（只报站点级键 = CRC-32("cookie:<名>")，不报名、不报值），
-- 主控按站点累计。成熟的站点下发已知名集合，节点把"成熟站点出现没见过的 Cookie 名"
-- 也算 Cookie 偏离（进档位 Cookie 变体）；名集合里的定型 Cookie 另作 typed_params 下发。
--   waf_adapt_sites.cookie_samples / cookie_day_bits / cookie_last_day：带 Cookie 的干净样本数与出现天位图；
--   waf_adapt_cookies：每站每 Cookie 一行，类型冲突（某小时报 text 或与已记类型不同）永久不定型。
ALTER TABLE waf_adapt_sites
    ADD COLUMN cookie_samples bigint NOT NULL DEFAULT 0 CHECK (cookie_samples >= 0),
    ADD COLUMN cookie_day_bits integer NOT NULL DEFAULT 0 CHECK (cookie_day_bits BETWEEN 0 AND 65535),
    ADD COLUMN cookie_last_day integer NOT NULL DEFAULT 0 CHECK (cookie_last_day >= 0);

CREATE TABLE waf_adapt_cookies (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    cookie_key text NOT NULL CHECK (cookie_key ~ '^00000000[0-9a-f]{8}$'),
    value_type text NOT NULL CHECK (value_type IN ('number', 'ident', 'text', 'json', 'binary', 'url')),
    conflict boolean NOT NULL,
    max_len_bucket smallint NOT NULL CHECK (max_len_bucket BETWEEN 0 AND 7),
    charset integer NOT NULL CHECK (charset BETWEEN 0 AND 8191),
    seen bigint NOT NULL CHECK (seen > 0),
    sources bigint NOT NULL,
    day_bits integer NOT NULL CHECK (day_bits BETWEEN 1 AND 65535),
    last_day integer NOT NULL CHECK (last_day > 0),
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL CHECK (last_seen >= first_seen),
    PRIMARY KEY (tenant_scope_id, site_id, cookie_key),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES waf_adapt_sites(tenant_scope_id, site_id) ON DELETE CASCADE
);

REVOKE ALL ON waf_adapt_cookies FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON waf_adapt_cookies TO cdnca_control_app, cdnca_control_runtime;
