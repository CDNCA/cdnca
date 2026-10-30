-- 547（fix-nodeipgeo，主会话 10-27 预留）：编辑节点 → IP 归属自动解析 + 人工修正。
-- node_ip_location_resolutions：每个节点最近一次用主控 IP 情报库解析出的自动值（依据的地址、库版本、时间）；
-- nodes.management_settings.ip_location 仍是生效值（条件匹配读它），新增可选键 ip_location_manual
-- 记管理员修正过的字段（自动解析不覆盖）；存量节点里已填的字段视为人工值。
-- edge_node_network_marks.locations_sha256：节点归属摘要（NULL = 尚未记录：首次扫描只记录不重发）。
-- 前驱 546（fix-ticket2 546_ticket_notification_choices），守卫钉 546 校验和。
LOCK TABLE schema_migrations, nodes, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_547_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 546 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 546 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=546 AND
        migration_id='546_ticket_notification_choices' AND
        checksum_sha256='fc87066c830bf3d307312bfcbacb9e12911f551541a4e03f14caaa18ae7aa554' AND
        down_checksum_sha256='ede77a7148f0c967071a93d0a3ffa9404929f754e4cc9c6af3e8cc8a9ae9ad85' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_ip_location_resolutions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 547 requires the exact verified 546 release head' USING ERRCODE='P5470';
    END IF;
END;
$migration_547_up$;

CREATE TABLE node_ip_location_resolutions (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    -- the node's addresses when resolved, in try order (IPv4, IPv6, secondary IPs)
    addresses text[] NOT NULL CHECK (cardinality(addresses) <= 66),
    outcome text NOT NULL CHECK (outcome IN ('resolved', 'unresolved', 'no_library')),
    address inet,
    country text NOT NULL DEFAULT '' CHECK (char_length(country) <= 128),
    province text NOT NULL DEFAULT '' CHECK (char_length(province) <= 128),
    city text NOT NULL DEFAULT '' CHECK (char_length(city) <= 128),
    isp text NOT NULL DEFAULT '' CHECK (char_length(isp) <= 128),
    country_code text NOT NULL DEFAULT '' CHECK (country_code ~ '^([A-Z]{2})?$'),
    library_revision bigint NOT NULL DEFAULT 0 CHECK (library_revision >= 0),
    library_version text NOT NULL DEFAULT '' CHECK (char_length(library_version) <= 128),
    resolved_at timestamptz NOT NULL CHECK (isfinite(resolved_at)),
    CHECK ((outcome = 'resolved') = (address IS NOT NULL))
);
REVOKE ALL ON node_ip_location_resolutions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_ip_location_resolutions TO cdnca_control_app, cdnca_control_runtime;

ALTER TABLE nodes ADD CONSTRAINT nodes_ip_location_manual_547_check CHECK (
    management_settings->'ip_location_manual' IS NULL OR (
        jsonb_typeof(management_settings->'ip_location_manual') = 'array' AND
        jsonb_array_length(management_settings->'ip_location_manual') <= 5 AND
        management_settings->'ip_location_manual' <@ '["country", "province", "city", "isp", "country_code"]'::jsonb));

-- Every value stored so far was typed by an administrator.
UPDATE nodes SET management_settings = management_settings || jsonb_build_object('ip_location_manual',
    (SELECT jsonb_agg(location.key ORDER BY location.key) FROM jsonb_each_text(management_settings->'ip_location') location
     WHERE location.key IN ('country', 'province', 'city', 'isp', 'country_code') AND location.value <> ''))
WHERE EXISTS (SELECT 1 FROM jsonb_each_text(management_settings->'ip_location') location
    WHERE location.key IN ('country', 'province', 'city', 'isp', 'country_code') AND location.value <> '');

ALTER TABLE edge_node_network_marks
    ADD COLUMN locations_sha256 bytea CHECK (locations_sha256 IS NULL OR octet_length(locations_sha256) = 32);
