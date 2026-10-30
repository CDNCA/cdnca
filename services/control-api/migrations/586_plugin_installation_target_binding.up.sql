-- 586（fix-plugconfirm3，占位号；合入时按集成头连号并重钉前驱）：插件安装 head 记录插件类型与受保护的本地目标绑定。
-- 报告第 4 节第 4 点：租户插件不能把“当前调用租户”直接当作已授权目标。
-- 1) entrypoint_type：授权端签名的插件类型（来自已验证清单），必须与 resource_scope 一致、不可改写；
--    主控据此决定“去主题管理/去规则包”和物化时匹配哪类制品，不由前端或 plugin_id 猜。
-- 2) 目标绑定：同一授权在本主控只能落到一个本地目标（head 的 tenant_scope_id + installation_id，
--    145 起不可改）。唯一索引保证另一个租户无法再为同一授权建 head，跨目标确认被拒绝。
-- 既有 head（测试机）按本地已物化的来源回填插件类型：平台 head 看 market_data_pack_sources.kind，
-- 租户 head 看 plugin_ui_pages / plugin_providers；推不出或同一授权已有多个本地目标时拒绝（P5861）。
-- 前驱：585（plugin_installation_resource_scope，fix-plugconfirm）。
LOCK TABLE schema_migrations, plugin_installation_heads, market_data_pack_sources, plugin_ui_pages, plugin_providers
    IN ACCESS EXCLUSIVE MODE;

DO $migration_586_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 585 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 585 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=585 AND
        migration_id='585_plugin_installation_resource_scope' AND
        checksum_sha256='2dfa02ec0d753032d123fa0bb5c7691b6717d24c86e3e8eab1e3dfbbf3bc3f33' AND
        down_checksum_sha256='6bd2fa2c71405a25331e49853120762d67aa38581b92c72841c3e7cd225858af' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='plugin_installation_heads' AND column_name='entrypoint_type'
       ) THEN
        RAISE EXCEPTION 'migration 586 requires the exact verified 585 release head' USING ERRCODE='P5860';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_installation_heads GROUP BY authorization_id HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'migration 586 found an authorization with several local targets' USING ERRCODE='P5861';
    END IF;
END;
$migration_586_up$;

ALTER TABLE plugin_installation_heads ADD COLUMN entrypoint_type text;
-- 回填不是业务状态转移（不加 revision），581 的 head 转移触发器会拒绝（P1451）：回填期间停用，表已 ACCESS EXCLUSIVE 锁定。
ALTER TABLE plugin_installation_heads DISABLE TRIGGER plugin_installation_heads_transition_581;
UPDATE plugin_installation_heads head SET entrypoint_type=CASE
    WHEN head.resource_scope='platform' THEN (
        SELECT CASE min(source.kind) WHEN 'market_theme' THEN 'theme' ELSE 'rule_pack' END
        FROM market_data_pack_sources source WHERE source.plugin_id=head.plugin_id HAVING count(DISTINCT source.kind)=1)
    WHEN EXISTS (SELECT 1 FROM plugin_ui_pages page WHERE page.plugin_id=head.plugin_id) AND
         NOT EXISTS (SELECT 1 FROM plugin_providers provider WHERE provider.plugin_id=head.plugin_id) THEN 'ui_page'
    WHEN EXISTS (SELECT 1 FROM plugin_providers provider WHERE provider.plugin_id=head.plugin_id) AND
         NOT EXISTS (SELECT 1 FROM plugin_ui_pages page WHERE page.plugin_id=head.plugin_id) THEN 'external_https'
END;
ALTER TABLE plugin_installation_heads ENABLE TRIGGER plugin_installation_heads_transition_581;
DO $migration_586_backfill$
BEGIN
    IF EXISTS (SELECT 1 FROM plugin_installation_heads WHERE entrypoint_type IS NULL) THEN
        RAISE EXCEPTION 'migration 586 cannot derive the plugin type of an existing installation' USING ERRCODE='P5861';
    END IF;
END;
$migration_586_backfill$;
ALTER TABLE plugin_installation_heads ALTER COLUMN entrypoint_type SET NOT NULL;
ALTER TABLE plugin_installation_heads
    ADD CONSTRAINT plugin_installation_heads_entrypoint_586_check CHECK (
        (resource_scope='platform' AND entrypoint_type IN ('theme','rule_pack')) OR
        (resource_scope='tenant' AND entrypoint_type IN ('external_https','ui_page')));

-- 目标绑定：一个授权只有一个本地目标。
CREATE UNIQUE INDEX plugin_installation_heads_authorization_586_uk
    ON plugin_installation_heads(authorization_id);

CREATE FUNCTION validate_plugin_installation_entrypoint_586()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.entrypoint_type IS DISTINCT FROM OLD.entrypoint_type THEN
        RAISE EXCEPTION 'plugin installation entrypoint type is immutable' USING ERRCODE='P5862';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_installation_heads_entrypoint_586
BEFORE UPDATE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_entrypoint_586();
