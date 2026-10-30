-- 517（r136 fp-cert，CERT-04；分支占位 514，merge-p9 改为 517、前驱 516）。
-- 证书申请可按订单选签发机构（issuer），用户默认签发机构，订单与证书资产可写名称和备注。
-- issuer 在建订单时按「显式 > 用户默认 > 平台默认」解析后写入并冻结；续签子订单沿用父订单。
-- NULL issuer 只出现在 517 之前的存量订单上：运行时仍按平台默认签发机构处理（与 517 前一致）。
LOCK TABLE schema_migrations, certificate_orders, certificate_assets, certificate_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_517_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 516 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=516 AND
        migration_id='516_site_user_defaults_rule_copies' AND
        checksum_sha256='99cf1259aa23431c7c43498b1fd4c88914d05f677814347de8ebaa2dc9ad201a' AND
        down_checksum_sha256='2db6c17538e9db2e5176b4be078e808ed20b9070d585de4e506735e9ce2bc79f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 517 requires the exact verified 516 head' USING ERRCODE='P5170';
    END IF;
END;
$migration_517_up$;

ALTER TABLE certificate_orders
    ADD COLUMN issuer text CHECK (issuer IS NULL OR issuer IN ('lets_encrypt', 'zerossl', 'google_trust')),
    ADD COLUMN name text NOT NULL DEFAULT '' CHECK (
        octet_length(name) <= 128 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (
        char_length(remark) <= 256 AND remark = btrim(remark) AND remark !~ '[[:cntrl:]]');

ALTER TABLE certificate_assets
    ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (
        char_length(remark) <= 256 AND remark = btrim(remark) AND remark !~ '[[:cntrl:]]');

ALTER TABLE certificate_user_defaults
    ADD COLUMN issuer text CHECK (issuer IS NULL OR issuer IN ('lets_encrypt', 'zerossl', 'google_trust')),
    ADD CONSTRAINT certificate_user_defaults_issuer_517_check CHECK (certificate_type = 'acme' OR issuer IS NULL);

-- 订单的签发机构、名称、备注建单后不可改（048 的保护触发器只列了 048 时的列）。
CREATE FUNCTION protect_certificate_order_metadata_517() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.issuer IS DISTINCT FROM OLD.issuer OR NEW.name IS DISTINCT FROM OLD.name OR
       NEW.remark IS DISTINCT FROM OLD.remark THEN
        RAISE EXCEPTION 'certificate order issuer, name and remark are immutable' USING ERRCODE='P5171';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER certificate_orders_metadata_immutable_517 BEFORE UPDATE OF issuer, name, remark ON certificate_orders
FOR EACH ROW EXECUTE FUNCTION protect_certificate_order_metadata_517();
ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_metadata_immutable_517;
REVOKE ALL ON FUNCTION protect_certificate_order_metadata_517() FROM PUBLIC, cdnca_control_app;
