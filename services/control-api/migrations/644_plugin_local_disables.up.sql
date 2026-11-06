-- 644（前驱 643_probe_dnspup_followup）：本主控的插件本机停用名单。
--
--   1. plugin_local_disables：每个被本主控停用的插件一行，记它的功能码（module.* / pack.* / theme.*）、停用人、时间与原因。
--      entitlementguard 读取租约功能集时减去这里的功能码（ReadValidFeatures / GrantedModules / CheckFeature），
--      于是本机所有租户都用不了该功能，相当于该功能码在本机不生效；授权、租约、计费都不动。删除这一行即重新启用。
--      只收插件功能码：sites.manage 之类的基础功能码不是插件，不能在这里停。
--   2. plugin_local_disable_requests：停用 / 重新启用两个写接口的 Idempotency-Key 回执（同一用户同一键重放同一结果，
--      请求体不同答 409）。
-- 只加表，不改已有表与数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_644_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 643 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 643 OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.users') IS NULL OR
          to_regclass(current_schema() || '.plugin_local_disables') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 644 requires the exact verified 643 release head' USING ERRCODE='P6440';
    END IF;
END;
$migration_644_up$;

CREATE TABLE plugin_local_disables (
    plugin_id text PRIMARY KEY CHECK (char_length(plugin_id) BETWEEN 3 AND 128 AND plugin_id ~ '^[a-z0-9]+([.-][a-z0-9]+)+$'),
    feature_code text NOT NULL UNIQUE CHECK (char_length(feature_code) <= 96 AND
        feature_code ~ '^(module|pack|theme)\.[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'),
    disabled_by_user_id uuid NOT NULL,
    disabled_at timestamptz NOT NULL,
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500)
);

CREATE TABLE plugin_local_disable_requests (
    actor_user_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    operation text NOT NULL CHECK (operation IN ('disable', 'enable')),
    request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (actor_user_id, idempotency_key)
);
CREATE INDEX plugin_local_disable_requests_created_644_idx ON plugin_local_disable_requests (created_at);

REVOKE ALL ON plugin_local_disables, plugin_local_disable_requests FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON plugin_local_disables, plugin_local_disable_requests TO cdnca_control_app, cdnca_control_runtime;
