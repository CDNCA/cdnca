-- 497（r136 region-override-trim，分支占位 491，merge-p4 改号 497，前驱 496_l4_origin_pool_acl）。
-- 用户 10-25 08:1x：资源配置、默认配置里「建站/建转发/签证书时才取值」的区域覆盖去掉，只有默认
-- 配置 website.other 的 GZIP 开关与类型（节点按节点渲染）保留。控制端保存时已拒绝；这里兜底清掉
-- 已存修订里的这类覆盖（全新安装本应没有）：
--   resources.overrides 清空；defaults.overrides 每条只留 website.other，load_balancing、
--   websocket_enabled 取全局值（与 Go validateDefaults 归一一致），什么都不剩的整条删除。
-- 修订不可变、快照哈希被预检与边缘发布记录引用：只在确有改动的修订上临时停用保护触发器改写
-- 快照与哈希，并同步预检/边缘发布里的哈希。回退不恢复被清掉的覆盖。
LOCK TABLE schema_migrations, system_configuration_revisions, system_configuration_preflights,
    system_configuration_edge_publications IN ACCESS EXCLUSIVE MODE;

DO $migration_497_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 496 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 496 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=496 AND
        migration_id='496_l4_origin_pool_acl' AND
        checksum_sha256='5e4af277f365757f7f882ab8f0597a46ea8f0d05966bddc945de7b004646229d' AND
        down_checksum_sha256='4c36faa85650454c3518caebdb36709147e6bfc641248ea7a5f7f2bbf8d7c0aa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.system_configuration_trim_region_overrides_497(jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 497 requires the exact verified 496 release head' USING ERRCODE='P4970';
    END IF;
END;
$migration_497_up$;

-- 输入/输出都是整个快照文档 {"schema":...,"configuration":{...}}。
CREATE FUNCTION system_configuration_trim_region_overrides_497(document jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT jsonb_set(jsonb_set(document, '{configuration,resources,overrides}', '[]'::jsonb),
        '{configuration,defaults,overrides}', COALESCE((
            SELECT jsonb_agg(jsonb_set(item, '{values}', jsonb_build_object('website', jsonb_build_object(
                'other', item->'values'->'website'->'other' || jsonb_build_object(
                    'load_balancing', document->'configuration'->'defaults'->'website'->'other'->'load_balancing',
                    'websocket_enabled', document->'configuration'->'defaults'->'website'->'other'->'websocket_enabled'
                )))) ORDER BY ordinal)
            FROM jsonb_array_elements(document->'configuration'->'defaults'->'overrides') WITH ORDINALITY AS rows(item, ordinal)
            WHERE jsonb_typeof(item->'values'->'website'->'other') = 'object'
        ), '[]'::jsonb));
$$;

CREATE TEMPORARY TABLE system_configuration_trim_497 ON COMMIT DROP AS
SELECT platform_scope_id, revision, snapshot_sha256 AS old_sha256,
       convert_to(system_configuration_trim_region_overrides_497(
           convert_from(canonical_snapshot, 'UTF8')::jsonb)::text, 'UTF8') AS new_snapshot
FROM system_configuration_revisions;
DELETE FROM system_configuration_trim_497 trim USING system_configuration_revisions revision
WHERE revision.platform_scope_id=trim.platform_scope_id AND revision.revision=trim.revision AND
      revision.canonical_snapshot=trim.new_snapshot;

DO $migration_497_check$
BEGIN
    IF EXISTS (SELECT 1 FROM system_configuration_trim_497 WHERE NOT system_configuration_snapshot_is_valid(new_snapshot)) THEN
        RAISE EXCEPTION 'migration 497: a trimmed system configuration snapshot is invalid' USING ERRCODE='P4971';
    END IF;
END;
$migration_497_check$;

-- 投影一致性约束触发器是 DEFERRED：改写前设为 IMMEDIATE，否则 UPDATE 留下待处理事件，ENABLE TRIGGER 报 55006。
SET CONSTRAINTS system_configuration_revisions_projection_consistent IMMEDIATE;
ALTER TABLE system_configuration_revisions DISABLE TRIGGER system_configuration_revisions_protected;
ALTER TABLE system_configuration_preflights DISABLE TRIGGER system_configuration_preflights_append_only;
ALTER TABLE system_configuration_edge_publications DISABLE TRIGGER system_configuration_edge_publications_append_only;
UPDATE system_configuration_revisions revision
SET canonical_snapshot=trim.new_snapshot, snapshot_sha256=sha256(trim.new_snapshot)
FROM system_configuration_trim_497 trim
WHERE revision.platform_scope_id=trim.platform_scope_id AND revision.revision=trim.revision;
UPDATE system_configuration_preflights preflight SET snapshot_sha256=sha256(trim.new_snapshot)
FROM system_configuration_trim_497 trim
WHERE preflight.platform_scope_id=trim.platform_scope_id AND preflight.revision=trim.revision AND
      preflight.snapshot_sha256=trim.old_sha256;
UPDATE system_configuration_edge_publications publication SET system_snapshot_sha256=sha256(trim.new_snapshot)
FROM system_configuration_trim_497 trim
WHERE publication.platform_scope_id=trim.platform_scope_id AND publication.system_revision=trim.revision AND
      publication.system_snapshot_sha256=trim.old_sha256;
ALTER TABLE system_configuration_edge_publications ENABLE TRIGGER system_configuration_edge_publications_append_only;
ALTER TABLE system_configuration_preflights ENABLE TRIGGER system_configuration_preflights_append_only;
ALTER TABLE system_configuration_revisions ENABLE TRIGGER system_configuration_revisions_protected;
SET CONSTRAINTS system_configuration_revisions_projection_consistent DEFERRED;
