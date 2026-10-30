LOCK TABLE schema_migrations, region_catalog, node_ssh_install_jobs, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_528_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 527 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 527 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=527 AND
        migration_id='527_tenant_member_invitations_drop' AND
        checksum_sha256='810266afb33ef34a711d3da3e5606ea14819ca09491604e23ca24d1d822e2ce5' AND
        down_checksum_sha256='856a4c33b26b0e83167ce2185a1f3e84e3cf66ad3cd61ab2e5b046bcf263bb5d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
            table_name='region_catalog' AND column_name='code'
       ) THEN
        RAISE EXCEPTION 'migration 528 requires the exact verified 527 release head' USING ERRCODE='P5280';
    END IF;
END;
$migration_528_up$;

-- 528（r136 fz-x12，本地占位号 528，派单占位 535；合线时改号到实际头，并按惯例把前驱的
-- migration_id / checksum_sha256 / down_checksum_sha256 钉进上面的守卫，常量集中在
-- region_catalog_code_528_contract_test.go）。
-- 节点区域由主控下发：区域目录每个区域一个稳定的小写 ASCII 代号 code，节点按它匹配（错误页区域
-- 覆盖、条件回源 node_regions），主控经节点密钥文档 node_region 下发（能力 NODE_REGION=70）。
--   code 规则：名称“默认”为 default；名称的小写形式符合 ^[a-z0-9][a-z0-9-]{0,62}$、不形如
--   region-<数字> 且本平台未占用时取它；否则 region-<display_id>。插入时生成，之后不可改
--   （改名不改代号）。中文名照旧作显示名。
--   node_ssh_install_jobs.node_region：安装器去掉 --node-region（1.0.35 全新安装），删列。
--   edge_node_network_marks.regions_sha256：节点区域分配的标记；变了就重新发布所有租户作用域
--   （密钥文档里的 node_region 跟着变）。NULL = 还没记过。
CREATE FUNCTION region_catalog_code_528(scope_id uuid, region_name text, region_display_id bigint)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    candidate text := lower(btrim(region_name));
BEGIN
    IF btrim(region_name) = '默认' THEN
        candidate := 'default';
    END IF;
    IF candidate ~ '^[a-z0-9][a-z0-9-]{0,62}$' AND candidate !~ '^region-[0-9]+$' AND NOT EXISTS (
        SELECT 1 FROM region_catalog region WHERE region.platform_scope_id = scope_id AND region.code = candidate
    ) THEN
        RETURN candidate;
    END IF;
    RETURN 'region-' || region_display_id::text;
END;
$$;

ALTER TABLE region_catalog ADD COLUMN code text;

ALTER TABLE region_catalog DISABLE TRIGGER region_catalog_management_update_235;
DO $migration_528_backfill$
DECLARE
    item record;
BEGIN
    FOR item IN SELECT id, platform_scope_id, name, display_id FROM region_catalog ORDER BY display_id LOOP
        UPDATE region_catalog SET code = region_catalog_code_528(item.platform_scope_id, item.name, item.display_id)
        WHERE id = item.id;
    END LOOP;
END;
$migration_528_backfill$;
ALTER TABLE region_catalog ENABLE TRIGGER region_catalog_management_update_235;

ALTER TABLE region_catalog
    ALTER COLUMN code SET NOT NULL,
    ADD CONSTRAINT region_catalog_code_528_check CHECK (code ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    ADD CONSTRAINT region_catalog_scope_code_528_unique UNIQUE (platform_scope_id, code);

CREATE FUNCTION assign_region_catalog_code_528()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.code IS NOT NULL THEN
            RAISE EXCEPTION 'region catalog code is generated' USING ERRCODE = 'P5281';
        END IF;
        NEW.code := region_catalog_code_528(NEW.platform_scope_id, NEW.name, NEW.display_id);
    ELSIF NEW.code IS DISTINCT FROM OLD.code THEN
        RAISE EXCEPTION 'region catalog code is immutable' USING ERRCODE = 'P5281';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER region_catalog_code_528
BEFORE INSERT OR UPDATE OF code ON region_catalog
FOR EACH ROW EXECUTE FUNCTION assign_region_catalog_code_528();

ALTER TABLE node_ssh_install_jobs DROP COLUMN node_region;

ALTER TABLE edge_node_network_marks
    ADD COLUMN regions_sha256 bytea CHECK (regions_sha256 IS NULL OR octet_length(regions_sha256) = 32);
