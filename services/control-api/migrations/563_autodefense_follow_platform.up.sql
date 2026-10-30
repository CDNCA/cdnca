-- 563（fix-adglobal，占位号，合入时由主会话按集成头顺延并改钉前驱；前驱暂钉集成头 554_node_bandwidth_alerts）。
-- 智能自动防御做成全平台设置：站点模式新增 follow（跟随平台），跟随的站点按平台设置 default_mode 执行，
-- 平台默认改变时随下一次快照即时生效；单独设置的站点不变。
-- 平台设置 new_site_learning 并入 default_mode：开 → default_mode=learning（新站跟随平台）；关 → default_mode=off。
-- 已有的 off 行（旧的“新站默认关闭/未设置”）不改：它们是单独设置的值，管理员可批量“恢复跟随平台”。
-- 用户 10-17：1.0.35 为初始版本、上线全部重装，本迁移只做测试库可用的最小转换，不做旧版兼容。
LOCK TABLE schema_migrations, autodefense_sites, autodefense_platform_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_563_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 562 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 562 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=562 AND
        migration_id='562_autodefense_site_allows' AND
        checksum_sha256='fe5326b9df62c6a96ad5ef2ac1e081211c97e6bc826867873a2d0924110ac985' AND
        down_checksum_sha256='91add6f612ad5bc32819f719a510df80b2c9011b5b008f5fc5e1a381e7232117' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM autodefense_sites WHERE mode='follow') THEN
        RAISE EXCEPTION 'migration 563 requires the exact verified 562 release head' USING ERRCODE='P5630';
    END IF;
END;
$migration_563_up$;

ALTER TABLE autodefense_sites DROP CONSTRAINT autodefense_sites_mode_check;
ALTER TABLE autodefense_sites ADD CONSTRAINT autodefense_sites_mode_check
    CHECK (mode IN ('off', 'learning', 'observe', 'protect', 'follow'));

UPDATE autodefense_platform_settings
SET settings = (settings - 'new_site_learning') || jsonb_build_object('default_mode',
        CASE WHEN COALESCE((settings->>'new_site_learning')::boolean, true) THEN 'learning' ELSE 'off' END)
WHERE NOT settings ? 'default_mode';

-- 学习中的行原本来自“新建站点自动进入学习中”（EnrollNewSite 只写 learning 行），平台默认为 learning 时改为跟随平台，
-- 生效模式不变。人工选过“开始学习”的站点无法区分，同样转为跟随（初始版本，可接受）。
UPDATE autodefense_sites SET mode='follow', revision=revision+1
WHERE mode='learning' AND NOT EXISTS (
    SELECT 1 FROM autodefense_platform_settings WHERE settings->>'default_mode' <> 'learning');

-- 没有设置行的站点（未单独设置）跟随平台：补一行默认值，快照、联防只覆盖有行的站点。
-- max_level 为注册表默认（不设上限，可到 XDP），模块由读取时补齐（CompleteModules）。
INSERT INTO autodefense_sites(tenant_scope_id,site_id,mode,sensitivity,maturity,cross_site,circuit_state,circuit_reason,
    circuit_since,circuit_manual_resume,observe_until,last_event_at,max_level,modules,revision,updated_at)
SELECT s.scope_id, s.id, 'follow',
    COALESCE((SELECT p.settings->>'default_sensitivity' FROM autodefense_platform_settings p), 'medium'),
    'prior', true, 'closed', NULL, NULL, false, NULL, NULL,
    '{"field":"site.max_level","state":"auto","manual":5,"min":0,"max":5}'::jsonb, '[]'::jsonb, 2, now()
FROM sites s
WHERE s.deleted_at IS NULL AND NOT EXISTS (
    SELECT 1 FROM autodefense_sites a WHERE a.tenant_scope_id=s.scope_id AND a.site_id=s.id);
