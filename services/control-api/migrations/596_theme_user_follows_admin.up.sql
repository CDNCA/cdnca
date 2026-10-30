-- 596（fix-themefollow，用户 10-29 定"真正联动"）：用户端主题"跟随管理端"改为实时联动。
-- 以前"跟随官方/恢复官方"把当时的管理端主题包钉成 user 行，之后管理端换主题用户端不跟着变。
-- 现在 slot='user' 的行可以不带包（package_sha256 IS NULL）= 跟随管理端：用户端（登录页、
-- 没有自有主题的租户、品牌名、站点主题插件识别）实时取管理端当前主题。'all' 行本来就是一个
-- 主题同时服务两端，语义为"管理端=X、用户端跟随"。只有带包的 user 行才是用户端手选。
-- 回填：用户端最新一行是带包的 user 行、且包等于当前管理端包（尚无管理端激活时为内置 default
-- 主题）的，视为跟随，追加一行不带包的 user 行（沿用该行的平台与操作人，request_id=migration-596）；
-- 其余保持手选。已有行不改写。
-- 前驱：595_entitlement_customer_display。
LOCK TABLE schema_migrations, theme_activations, theme_packages IN ACCESS EXCLUSIVE MODE;

DO $migration_596_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 595 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 595 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=595 AND
        migration_id='595_entitlement_customer_display' AND
        checksum_sha256='8535da99c67bb01647bb0e481037dd7151c6ea82f0f6c7c17500a43869327a3a' AND
        down_checksum_sha256='01ebe57d761db0c7bc7ef7c3c44c0b72eaa2e23b62d6f8ad7e3384fc70406201' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='theme_activations_user_follows_596'
       ) THEN
        RAISE EXCEPTION 'migration 596 requires the exact verified 595 release head' USING ERRCODE='P5960';
    END IF;
END;
$migration_596_up$;

ALTER TABLE theme_activations ALTER COLUMN package_sha256 DROP NOT NULL,
    ADD CONSTRAINT theme_activations_user_follows_596 CHECK (package_sha256 IS NOT NULL OR slot = 'user');

-- 360 的校验：带包的行要求包已下载且未移除；不带包的跟随行（只许 user 槽，见上面约束）不查包。
CREATE OR REPLACE FUNCTION validate_theme_activation_360()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('theme-activation', 0));
    IF NEW.revision <> COALESCE((SELECT max(revision) FROM theme_activations), 0) + 1 OR
       NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.platform_scope_id AND kind = 'platform' AND tenant_id IS NULL) OR
       (NEW.package_sha256 IS NOT NULL AND
        NOT EXISTS (SELECT 1 FROM theme_packages WHERE package_sha256 = NEW.package_sha256 AND removed_at IS NULL)) THEN
        RAISE EXCEPTION 'invalid theme activation' USING ERRCODE = 'P3601';
    END IF;
    RETURN NEW;
END;
$$;

-- 360 的事实保护：不能移除管理端当前主题包（最新 admin/all 行）和最新一行的包。最新一行
-- 可能是不带包的跟随行，所以管理端指针单独保护。
CREATE OR REPLACE FUNCTION protect_theme_facts_360()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME <> 'theme_packages' OR TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'theme facts are immutable' USING ERRCODE = 'P3603';
    END IF;
    IF ROW(NEW.package_sha256, NEW.theme_id, NEW.version, NEW.source, NEW.requires_feature, NEW.package_body,
           NEW.css_sha256, NEW.css_body, NEW.json_sha256, NEW.json_body, NEW.downloaded_by_user_id, NEW.downloaded_at)
       IS NOT DISTINCT FROM
       ROW(OLD.package_sha256, OLD.theme_id, OLD.version, OLD.source, OLD.requires_feature, OLD.package_body,
           OLD.css_sha256, OLD.css_body, OLD.json_sha256, OLD.json_body, OLD.downloaded_by_user_id, OLD.downloaded_at) THEN
        -- Only the removal mark moves, and never off an active package.
        IF NEW.removed_at IS NOT NULL AND (NEW.package_sha256 = (
            SELECT package_sha256 FROM theme_activations ORDER BY revision DESC LIMIT 1
        ) OR NEW.package_sha256 = (
            SELECT package_sha256 FROM theme_activations WHERE slot IN ('admin', 'all') ORDER BY revision DESC LIMIT 1
        )) THEN
            RAISE EXCEPTION 'the active theme package cannot be removed' USING ERRCODE = 'P3602';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'theme facts are immutable' USING ERRCODE = 'P3603';
END;
$$;

INSERT INTO theme_activations(revision, platform_scope_id, package_sha256, activated_by_user_id, request_id, activated_at, slot)
SELECT (SELECT max(revision) FROM theme_activations) + 1, latest.platform_scope_id, NULL, latest.activated_by_user_id,
       'migration-596', now(), 'user'
FROM (SELECT * FROM theme_activations WHERE slot IN ('user', 'all') ORDER BY revision DESC LIMIT 1) latest
JOIN theme_packages package ON package.package_sha256 = latest.package_sha256
LEFT JOIN (SELECT package_sha256 FROM theme_activations WHERE slot IN ('admin', 'all') ORDER BY revision DESC LIMIT 1) admin ON true
WHERE latest.slot = 'user' AND (
    latest.package_sha256 = admin.package_sha256 OR
    (admin.package_sha256 IS NULL AND package.theme_id = 'default' AND package.source = 'builtin')
);

REVOKE ALL ON FUNCTION validate_theme_activation_360(), protect_theme_facts_360() FROM PUBLIC;
