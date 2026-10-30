LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_414_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 413 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 413 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=413 AND
        migration_id='413_site_status_recovery_write_requests' AND
        checksum_sha256='26e6ba27e1b9ab73c841f66d79ff221c34d4630798c0478aa464d8b1a4a6d7c9' AND
        down_checksum_sha256='9b20e44404803f3c59506d1233e81a933d450d23f752b0c18d4729bf31f10560' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.autodefense_module_values') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 414 requires the exact verified 413 release head' USING ERRCODE='P4140';
    END IF;
END;
$migration_414_up$;

-- 414（r136 ad-16，占位 = 集成头 413 + 1，合入时改号）。Module "智能自动"
-- values as the nodes report them (ADR 0010 section 7A; node autonomy, user
-- 10-19 06:20: each node computes its own automatic value, the control plane
-- only shows it). One row per target item and node, the newest report wins:
--   value / previous / reason: the node's value in force (or, suggest, the
--     value it would apply) and why;
--   suggest: the value is a suggestion (suggest mode, or auto without
--     module.autodefense.auto), never in force;
--   frozen_until: the node froze the item after its fourth reversal within
--     an hour.
-- target_kind site: tenant_scope_id + site_id (cascade with the site);
-- port_group: node_id + port_group_id (cascade with the node).
CREATE TABLE autodefense_module_values (
    target_kind text NOT NULL CHECK (target_kind IN ('site', 'port_group')),
    tenant_scope_id uuid,
    site_id uuid,
    port_group_id text CHECK (port_group_id IS NULL OR length(port_group_id) BETWEEN 1 AND 64),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    module text NOT NULL CHECK (module IN ('cc', 'waf', 'scan', 'bot', 'l4')),
    field text NOT NULL CHECK (length(field) BETWEEN 1 AND 96),
    value bigint NOT NULL,
    previous bigint NOT NULL,
    reason text NOT NULL CHECK (length(reason) <= 512),
    suggest boolean NOT NULL,
    frozen_until timestamptz CHECK (frozen_until IS NULL OR isfinite(frozen_until)),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    CHECK ((target_kind = 'site') = (tenant_scope_id IS NOT NULL AND site_id IS NOT NULL AND port_group_id IS NULL)),
    CHECK ((target_kind = 'port_group') = (tenant_scope_id IS NULL AND site_id IS NULL AND port_group_id IS NOT NULL)),
    CHECK ((module = 'l4') = (target_kind = 'port_group')),
    CHECK (NOT (suggest AND frozen_until IS NOT NULL)),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX autodefense_module_values_site_key
    ON autodefense_module_values (tenant_scope_id, site_id, module, field, node_id) WHERE target_kind = 'site';
CREATE UNIQUE INDEX autodefense_module_values_port_group_key
    ON autodefense_module_values (node_id, port_group_id, field) WHERE target_kind = 'port_group';

REVOKE ALL ON autodefense_module_values FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_module_values TO cdnca_control_app, cdnca_control_runtime;
