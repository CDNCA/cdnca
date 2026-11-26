-- 702（前驱 701_edge_publication_node_settings）。
-- 每次站点对象发布记下它的承载节点：各网站、各四层转发由哪些节点承载（线路分组当前修订的启用端点、套餐主备分组、
-- 升级线路、L2 成员；no 键 = 无可用线路分组，所有目标节点都承载）。key document 里按节点屏蔽的网站与转发由此而来。
-- 系统停止 overlay 与节点设置重发不读租户可能改过而未发布的行：屏蔽集合取基准发布记下的承载节点，未发布的线路分组修改
-- 不提前生效（否则旧节点停止承载、新节点又没收到，网站在所有节点上都不可用）。没有记录的旧发布按当前行计算。
-- serving：{"node_sets":[[节点...],...],"sites":{网站:下标|null},"streams":{转发:下标|null}}，null 为无可用线路分组。
-- 行不可改、不可删。错误码：头检查与 down 头检查 P7020；修改或删除 P7021。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_702_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 701 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 701 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=701 AND
        migration_id='701_edge_publication_node_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.edge_publication_serving_nodes') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 702 requires the exact verified 701 release head' USING ERRCODE='P7020';
    END IF;
END;
$migration_702_up$;

CREATE TABLE edge_publication_serving_nodes (
    config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    serving jsonb NOT NULL CHECK (jsonb_typeof(serving)='object' AND jsonb_typeof(serving->'node_sets')='array'
        AND jsonb_typeof(serving->'sites')='object' AND jsonb_typeof(serving->'streams')='object'),
    created_at timestamptz NOT NULL
);

CREATE FUNCTION protect_edge_publication_serving_nodes_702()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'edge publication serving nodes are immutable' USING ERRCODE='P7021';
END;
$$;

CREATE TRIGGER edge_publication_serving_nodes_immutable_702
BEFORE UPDATE OR DELETE ON edge_publication_serving_nodes
FOR EACH ROW EXECUTE FUNCTION protect_edge_publication_serving_nodes_702();

REVOKE ALL ON edge_publication_serving_nodes FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_edge_publication_serving_nodes_702() FROM PUBLIC;
GRANT SELECT, INSERT ON edge_publication_serving_nodes TO cdnca_control_app, cdnca_control_runtime;
