-- 496（r136 stream-be，用户 10-25 03:0x「转发列表功能也不一致」；本地占位 490，merge-p3 合入改为 496、前驱 495）。
-- 四层转发：源站列表（多源站+权重+上下线）、定源、IPv6开启、ACL 默认行为与规则、管理员设置状态、批量写收据。
LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_496_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 495 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 495 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=495 AND
        migration_id='495_http_policy_header_vars_conditions' AND
        checksum_sha256='d1f710dfcc99d9063cd723ea76cb1c0b158b652393134b363550b3f2dd54bd6d' AND
        down_checksum_sha256='e511b05932fb54077d052a23f80e0714bb048efd2ea61c2aca7e2875d5371d4b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name IN ('origins', 'listen_ipv6', 'acl_default_action', 'acl_rules', 'admin_status')
       ) THEN
        RAISE EXCEPTION 'migration 496 requires the exact verified 495 release head' USING ERRCODE='P4960';
    END IF;
END;
$migration_496_up$;

-- 源站列表：1..64 个 {address, weight 1..100, down}，NULL = 只有 upstream_address/upstream_host 一个源站。
-- 有列表时 upstream_address 等于第一个源站（搜索、端口冲突、旧读取路径照旧）。
CREATE FUNCTION valid_l4_origins_496(origins jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE origin jsonb;
BEGIN
    IF jsonb_typeof(origins) IS DISTINCT FROM 'array' OR jsonb_array_length(origins) NOT BETWEEN 1 AND 64 OR
       (SELECT count(DISTINCT item->>'address') FROM jsonb_array_elements(origins) item) <> jsonb_array_length(origins) OR
       NOT EXISTS (SELECT 1 FROM jsonb_array_elements(origins) item WHERE NOT COALESCE((item->>'down')::boolean, false)) THEN
        RETURN false;
    END IF;
    FOR origin IN SELECT value FROM jsonb_array_elements(origins) LOOP
        IF jsonb_typeof(origin) IS DISTINCT FROM 'object' OR
           EXISTS (SELECT 1 FROM jsonb_object_keys(origin) keys(key) WHERE key NOT IN ('address', 'weight', 'down')) OR
           host((origin->>'address')::inet) IS DISTINCT FROM origin->>'address' OR
           masklen((origin->>'address')::inet) <> 32 + 96 * (family((origin->>'address')::inet) / 6) OR
           jsonb_typeof(origin->'weight') IS DISTINCT FROM 'number' OR (origin->>'weight') !~ '^[1-9][0-9]{0,2}$' OR
           (origin->>'weight')::integer > 100 OR
           (origin ? 'down' AND jsonb_typeof(origin->'down') IS DISTINCT FROM 'boolean') THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

-- ACL 规则：1..1024 条 {cidr, action allow|deny}，按顺序第一条命中生效；NULL = 无规则。
CREATE FUNCTION valid_l4_acl_rules_496(rules jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE rule jsonb;
BEGIN
    IF jsonb_typeof(rules) IS DISTINCT FROM 'array' OR jsonb_array_length(rules) NOT BETWEEN 1 AND 1024 THEN
        RETURN false;
    END IF;
    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) IS DISTINCT FROM 'object' OR
           (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(rule) keys(key)) IS DISTINCT FROM ARRAY['action','cidr']::text[] OR
           rule->>'action' NOT IN ('allow', 'deny') OR
           network((rule->>'cidr')::cidr)::text IS DISTINCT FROM rule->>'cidr' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

ALTER TABLE l4_forwards
    ADD COLUMN origins jsonb,
    ADD COLUMN listen_ipv6 boolean NOT NULL DEFAULT false,
    ADD COLUMN acl_default_action text NOT NULL DEFAULT 'allow',
    ADD COLUMN acl_rules jsonb,
    -- 管理员「设置状态」：normal 之外的转发不下发（与 enabled=false 一样撤下）。
    ADD COLUMN admin_status text NOT NULL DEFAULT 'normal',
    ADD CONSTRAINT l4_forwards_origins_496 CHECK (
        origins IS NULL OR (site_id IS NOT NULL AND upstream_address IS NOT NULL AND upstream_host IS NULL AND
            valid_l4_origins_496(origins) AND origins->0->>'address' = host(upstream_address))
    ),
    ADD CONSTRAINT l4_forwards_acl_496 CHECK (
        acl_default_action IN ('allow', 'deny') AND (acl_rules IS NULL OR valid_l4_acl_rules_496(acl_rules)) AND
        (site_id IS NOT NULL OR (acl_default_action = 'allow' AND acl_rules IS NULL AND NOT listen_ipv6))
    ),
    ADD CONSTRAINT l4_forwards_admin_status_496 CHECK (
        admin_status IN ('normal', 'locked', 'traffic_exceeded', 'package_expired')
    );

-- Intents of v11 streams carry endpoint.origins / endpoint.balance / listen_ipv6;
-- stripped of them the intent is a valid 341 intent.
CREATE FUNCTION validate_l4_runtime_spec_496(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE stripped jsonb := runtime_spec - 'listen_ipv6';
BEGIN
    IF runtime_spec ? 'endpoint' THEN
        stripped := jsonb_set(stripped, '{endpoint}', (runtime_spec->'endpoint') - 'origins' - 'balance');
    END IF;
    IF NOT validate_l4_runtime_spec_341(target_stream_id,target_scope_id,target_site_id,stripped) THEN
        RETURN false;
    END IF;
    IF (runtime_spec ? 'listen_ipv6' OR COALESCE(runtime_spec->'endpoint' ?| ARRAY['origins', 'balance'], false)) AND
       target_site_id IS NULL THEN
        RETURN false;
    END IF;
    IF runtime_spec ? 'listen_ipv6' AND runtime_spec->'listen_ipv6' IS DISTINCT FROM 'true'::jsonb THEN RETURN false; END IF;
    IF COALESCE(runtime_spec->'endpoint' ? 'balance', false) AND runtime_spec#>>'{endpoint,balance}' <> 'ip_hash' THEN
        RETURN false;
    END IF;
    IF COALESCE(runtime_spec->'endpoint' ? 'origins', false) THEN
        RETURN valid_l4_origins_496(runtime_spec#>'{endpoint,origins}') AND
            runtime_spec#>>'{endpoint,origins,0,address}' = runtime_spec#>>'{endpoint,address}';
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_341,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_496
    CHECK(validate_l4_runtime_spec_496(stream_id,scope_id,site_id,runtime_spec));

-- 批量添加 / 管理员批量操作：整批一个幂等收据。
ALTER TABLE l4_write_requests DROP CONSTRAINT l4_write_requests_operation_check,
    ADD CONSTRAINT l4_write_requests_operation_496 CHECK (
        operation IN ('stream.create', 'stream.update', 'stream.delete', 'stream.batch_create', 'stream.batch_action')
    );

REVOKE ALL ON FUNCTION valid_l4_origins_496(jsonb), valid_l4_acl_rules_496(jsonb),
    validate_l4_runtime_spec_496(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION valid_l4_origins_496(jsonb), valid_l4_acl_rules_496(jsonb),
            validate_l4_runtime_spec_496(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
