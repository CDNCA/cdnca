-- 607（fw-receipt，调度分配 control 607；前驱 606 = autodefense-ux 防火墙动作启停（merge-p40 改号 609→607））：
-- 防火墙动作租户默认的发布回执与上一稳定版本（LKG）。
--   174 站点策略头早有 active/lkg/deployment_state，回执由 firewallactioncontrol.ReceiptWorker 接上；
--   605 租户默认没有这些列，继承站点因此没有"已生效版本"，也没有"失败回退到 LKG"。
--   本迁移给租户默认加同样三列与同样的不变式：
--     deployment_state='active'  ⇔ active_revision=lkg_revision=revision；
--     pending/failed             ⇔ active_revision<revision 且 lkg_revision=active_revision。
--   继承站点下发：pending 下发当前修订；active/failed 下发 lkg 修订（lkg=0 不下发）。
--   守卫：保存新修订必须 revision+1、回到 pending、active/lkg 不变；回执只能 pending→active/failed、修订与文档不变。
LOCK TABLE schema_migrations, firewall_action_tenant_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_607_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 606 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 606 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=606 AND
        migration_id='606_firewall_action_enabled' AND
        checksum_sha256='0a4609f0c9f1ab71811796820a4abd48426553a2ece2fa975283ea18239ec0cc' AND
        down_checksum_sha256='e87eed431d8187086d47bd84b5c99a0382ff82dee4d8e619ea7904988d88723e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('firewall_action_tenant_defaults') IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='firewall_action_tenant_defaults' AND column_name='deployment_state'
       ) THEN
        RAISE EXCEPTION 'migration 607 requires the exact verified 606 release head' USING ERRCODE='P6070';
    END IF;
END;
$migration_607_up$;

-- 已有默认从未有过回执：pending、无 LKG（与站点策略初次保存一致）。
ALTER TABLE firewall_action_tenant_defaults
    ADD COLUMN active_revision bigint NOT NULL DEFAULT 0 CHECK(active_revision BETWEEN 0 AND 9007199254740991),
    ADD COLUMN lkg_revision bigint NOT NULL DEFAULT 0 CHECK(lkg_revision BETWEEN 0 AND 9007199254740991),
    ADD COLUMN deployment_state text NOT NULL DEFAULT 'pending' CHECK(deployment_state IN ('pending','active','failed')),
    ADD CONSTRAINT firewall_action_tenant_defaults_deployment_607 CHECK(
        (deployment_state='active' AND active_revision=revision AND lkg_revision=revision) OR
        (deployment_state IN ('pending','failed') AND active_revision<revision AND lkg_revision=active_revision)
    );

CREATE FUNCTION guard_firewall_action_tenant_default_607()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'firewall action tenant default identity is immutable' USING ERRCODE='P6051';
    END IF;
    IF NEW.revision=OLD.revision+1 THEN
        IF NEW.deployment_state<>'pending' OR NEW.active_revision<>OLD.active_revision OR NEW.lkg_revision<>OLD.lkg_revision THEN
            RAISE EXCEPTION 'firewall action tenant default candidate must preserve active LKG' USING ERRCODE='P6071';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revision=OLD.revision AND OLD.deployment_state='pending' AND NEW.deployment_state IN ('active','failed') AND
       NEW.document_bytes=OLD.document_bytes AND NEW.document_sha256=OLD.document_sha256 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid firewall action tenant default transition' USING ERRCODE='P6072';
END;
$$;

DROP TRIGGER firewall_action_tenant_defaults_guard_605 ON firewall_action_tenant_defaults;
CREATE TRIGGER firewall_action_tenant_defaults_guard_607
BEFORE UPDATE OR DELETE ON firewall_action_tenant_defaults
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_tenant_default_607();
