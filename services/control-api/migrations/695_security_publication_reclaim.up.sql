-- 695（前驱 694_package_change_current_entitlement_lines）。
-- 安全激活候选的节点已验证通过（healthy），晋升前同一 scope 的常规发布推高了 source revision（新站
-- 默认 WAF 候选 rev62 在节点 healthy 后，新站自动发布 rev63 到同一节点，晋升 CAS 失败转 failed），绑定的
-- last_claimed 已等于库版本，此后既不能再申领同一版本（本函数与 securitybinding.checkClaim 要求版本大于上次
-- 申领），自动重新下发（rebind）也不会再挑中它，站点终态无生效版本。
-- 本迁移只放开一种情形：同一库、同一版本重新申领，且上次申领（binding.last_bundle_id）的候选已失败/取消/过期
-- 并恢复完毕（节点已不运行它）。其余条件逐字同 470。重新申领由激活 worker 有界发起（internal/securityactivation
-- rebind.go，每个版本最多 5 次）。
-- 错误码：头检查 P6950；down 头检查 P6951。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_site_bindings, security_policy_publications IN SHARE ROW EXCLUSIVE MODE;

DO $migration_695_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 694 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 694 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=694 AND
        migration_id='694_package_change_current_entitlement_lines' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('validate_security_policy_publication_insert()') IS NULL THEN
        RAISE EXCEPTION 'migration 695 requires the exact verified 694 release head' USING ERRCODE='P6950';
    END IF;
END;
$migration_695_up$;

CREATE OR REPLACE FUNCTION validate_security_policy_publication_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding security_policy_site_bindings%ROWTYPE;
    last_policy_id uuid;
    last_detach boolean := false;
BEGIN
    SELECT * INTO binding FROM security_policy_site_bindings
    WHERE id = NEW.binding_id FOR UPDATE;
    IF FOUND AND binding.last_bundle_id IS NOT NULL THEN
        SELECT policy_id, detach INTO last_policy_id, last_detach FROM security_policy_publications WHERE id = binding.last_bundle_id;
    END IF;
    -- 未写明发布时生效库的写入方（470 之前的写法）：生效库就是绑定当前的库。
    IF binding.id IS NOT NULL AND NEW.expected_active_version > 0 AND NEW.expected_active_policy_id IS NULL THEN
        NEW.expected_active_policy_id := binding.policy_id;
    END IF;
    IF binding.id IS NULL OR binding.tenant_scope_id <> NEW.tenant_scope_id OR
       binding.site_id <> NEW.site_id OR
       binding.policy_kind <> NEW.policy_kind OR binding.revision <> NEW.expected_binding_revision OR
       COALESCE(binding.active_policy_version, 0) <> NEW.expected_active_version OR
       (NEW.expected_active_version > 0 AND NEW.expected_active_policy_id IS DISTINCT FROM binding.policy_id) OR
       (NEW.detach AND (binding.active_policy_version IS NULL OR NEW.policy_id <> binding.policy_id OR
                        NEW.policy_version <> binding.active_policy_version)) OR
       (NOT NEW.detach AND EXISTS (
           SELECT 1 FROM security_policies policy WHERE policy.id = NEW.policy_id AND policy.deleted_at IS NOT NULL
       )) OR
       (NOT NEW.detach AND NEW.policy_id = binding.policy_id AND (
           NEW.policy_version <= COALESCE(binding.active_policy_version, 0) OR
           (binding.last_claimed_policy_version IS NOT NULL AND last_policy_id = NEW.policy_id AND NOT last_detach AND
            NEW.policy_version <= binding.last_claimed_policy_version AND NOT (
                NEW.policy_version = binding.last_claimed_policy_version AND
                NEW.policy_version > COALESCE(binding.active_policy_version, 0) AND EXISTS (
                    SELECT 1 FROM security_policy_activation_candidates candidate
                    WHERE candidate.tenant_scope_id = binding.tenant_scope_id AND candidate.binding_id = binding.id
                      AND candidate.last_bundle_id = binding.last_bundle_id
                      AND candidate.candidate_status IN ('failed','cancelled','expired')
                      AND candidate.recovered_at IS NOT NULL
                )))
       )) THEN
        RAISE EXCEPTION 'security publication binding or version conflict';
    END IF;
    RETURN NEW;
END;
$$;
