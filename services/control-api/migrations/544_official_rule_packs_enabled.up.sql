-- 544（fix-userpacks，用户 10-27：官方规则包默认不生效，要用户自己打开）：官方免费系统规则包
-- 默认启用。419 起主控给每个官方免费系统包写一条自己的平台行（无用户、inherit、allow_lower），
-- inherit 在平台层等于“系统默认：关闭”，所以只有 454 的 system/waf-php-vpatch 是 enabled。
-- 本迁移把这些主控自己写的平台行改为 enabled（管理员自己写的行不动，管理员仍可在管理端关闭），
-- 新到的官方免费包由 artifactsync.openOfficialPack 直接写 enabled；各网站的挂载由主控在下一轮
-- 制品同步时补齐并经系统重新发布通道下发（rulepackcontrol.DefaultOnSitesTx）。
-- 前驱 543（ticket_events），守卫钉 543 校验和。
LOCK TABLE schema_migrations, rule_pack_enablements, local_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_544_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 543 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 543 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=543 AND
        migration_id='543_ticket_events' AND
        checksum_sha256='a4f0e03aa59fc4da8e7ee88cde19669424d616b0a6ec3e454041045abd1bea30' AND
        down_checksum_sha256='ad27f2b6f0abcaae94d95b75538c833d33cf76519fb1c409d865eca200586e4c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 544 requires the exact verified 543 release head' USING ERRCODE='P5440';
    END IF;
END;
$migration_544_up$;

UPDATE rule_pack_enablements enablement SET state='enabled', updated_at=CURRENT_TIMESTAMP
    FROM rule_packs pack
    WHERE pack.pack_id=enablement.pack_id AND pack.layer='system' AND enablement.level='platform' AND
        enablement.rule_id IS NULL AND enablement.updated_by_user_id IS NULL AND enablement.state='inherit';

-- 已发布过挂载的网站不会被增量重算选中：清掉官方免费系统包的物化标记，下一轮制品同步重新
-- 物化它们（版本不变，只是再走一遍），并据此对全部网站重算一次挂载。
UPDATE local_artifacts local SET materialized_sha256=NULL, updated_at=CURRENT_TIMESTAMP
    FROM artifact_catalog_entries entry
    WHERE entry.artifact_id=local.artifact_id AND entry.kind='rule_pack' AND entry.requires_feature='' AND
        local.materialized_sha256 IS NOT NULL;
