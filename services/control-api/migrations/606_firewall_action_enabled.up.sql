-- 606（autodefense-ux2/ux3，原占位 608，hot-p40a 改号 606；前驱 605 = fw-default 租户默认防火墙动作 a0ae23c93）：
-- 防火墙动作策略加启停状态，停用不删记录（174 head 禁 DELETE）。
--   enabled=false：节点下发不带本站防火墙动作（edgepublish loadFirewallActionFactsSQL 过滤 head.enabled），
--   修订历史、LKG、回执不变；再启用即按当前有效修订恢复下发。
--   启停只改 enabled/updated_at，其余列（含 605 的 inherited）必须不变；候选写入、恢复继承（605）与发布回执转移必须保持 enabled 不变。
--   enabled 只管站点自有策略：继承中的站点（inherited）按租户默认下发，不看 enabled（edgepublish 继承分支）。
LOCK TABLE schema_migrations, firewall_action_policy_heads IN ACCESS EXCLUSIVE MODE;

DO $migration_606_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 605 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 605 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=605 AND
        migration_id='605_firewall_action_tenant_default' AND
        checksum_sha256='8cc0b9a80c8ad9d4376442823b43ec161cc206f70c0a5a5324ab9db70d73294e' AND
        down_checksum_sha256='5897c4abd70d72b2bac1483f3384b48716cee48d3d5f411b19db24aa65934d4f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('firewall_action_policy_heads') IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='firewall_action_policy_heads' AND column_name='enabled'
       ) THEN
        RAISE EXCEPTION 'migration 606 requires the exact verified 605 release head' USING ERRCODE='P6060';
    END IF;
END;
$migration_606_up$;

ALTER TABLE firewall_action_policy_heads ADD COLUMN enabled boolean NOT NULL DEFAULT true;

CREATE FUNCTION guard_firewall_action_head_606()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.created_at) OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'firewall action head identity is immutable' USING ERRCODE='P1742';
    END IF;
    IF NEW.enabled IS DISTINCT FROM OLD.enabled THEN
        IF ROW(NEW.document_bytes,NEW.document_sha256,NEW.revision,NEW.active_revision,NEW.lkg_revision,NEW.deployment_state,NEW.inherited)
           IS DISTINCT FROM
           ROW(OLD.document_bytes,OLD.document_sha256,OLD.revision,OLD.active_revision,OLD.lkg_revision,OLD.deployment_state,OLD.inherited) THEN
            RAISE EXCEPTION 'firewall action enable toggle must not change the policy' USING ERRCODE='P6061';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revision=OLD.revision+1 THEN
        IF NEW.deployment_state<>'pending' OR NEW.active_revision<>OLD.active_revision OR NEW.lkg_revision<>OLD.lkg_revision THEN
            RAISE EXCEPTION 'firewall action candidate must preserve active LKG' USING ERRCODE='P1743';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revision=OLD.revision AND OLD.deployment_state='pending' AND NEW.deployment_state IN ('active','failed') AND
       NEW.document_bytes=OLD.document_bytes AND NEW.document_sha256=OLD.document_sha256 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid firewall action head transition' USING ERRCODE='P1744';
END;
$$;

DROP TRIGGER firewall_action_head_guard_174 ON firewall_action_policy_heads;
CREATE TRIGGER firewall_action_head_guard_606
BEFORE UPDATE OR DELETE ON firewall_action_policy_heads
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_head_606();
