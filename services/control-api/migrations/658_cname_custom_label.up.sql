LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

-- 前驱校验：已验证的 657 发布头。
DO $migration_658_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 657 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 657 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=657 AND
        migration_id='657_account_registration_verification_template' AND
        checksum_sha256='c44839ba70ca9cdf232b50ac62590d132088fc71c9f277382baf009fc669bf01' AND
        down_checksum_sha256='6bf2874bf0c27ae8507fb012a4e1e3de04b06eaef34bc6208fe344b393511ef1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
        AND table_name='sites' AND column_name='cname_custom_label')
         OR to_regclass(current_schema() || '.cname_label_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 658 requires the exact verified 657 release head' USING ERRCODE='P6580';
    END IF;
END;
$migration_658_up$;

-- 658 管理员自定义 CNAME 名称。列或行为空时保持现状（自动生成 8 位标签）。
--   sites.cname_custom_label：网站自己 CNAME 的完整主机名标签（shop → shop.<CNAME 域名>）。
--   cname_label_settings：线路组的前缀模板，之后新分配的 CNAME 为 <前缀>-<8 位随机>。
--     用独立表而不是给 node_line_groups 加列：线路组每次更新都要推进 revision 并触发发布，
--     改名字不能引起这些副作用。已有 CNAME 不变。
-- 保留名由应用层拒绝，数据库只约束形状。
ALTER TABLE sites ADD COLUMN cname_custom_label text,
    ADD CONSTRAINT sites_cname_custom_label_658_check CHECK (cname_custom_label IS NULL OR
        (char_length(cname_custom_label) BETWEEN 1 AND 63 AND cname_custom_label ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'));

CREATE TABLE cname_label_settings (
    subject_kind text NOT NULL CHECK (subject_kind IN ('line_group')),
    subject_id uuid NOT NULL,
    -- 前缀后面还要留出 "-" 和 8 位随机字符。
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 54 AND label ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (subject_kind, subject_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON cname_label_settings TO cdnca_control_app, cdnca_control_runtime;
