-- 606 回滚：去掉防火墙动作启停。存在停用的策略时拒绝回滚（回滚后它会被静默重新下发）。
LOCK TABLE schema_migrations, firewall_action_policy_heads IN ACCESS EXCLUSIVE MODE;

DO $migration_606_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 606 OR
       (SELECT max(version) FROM schema_migrations) <> 606 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=606 AND
        migration_id='606_firewall_action_enabled' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 606 down requires the exact verified migration head' USING ERRCODE='P6062';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_action_policy_heads WHERE NOT enabled) THEN
        RAISE EXCEPTION 'migration 606 down refuses disabled firewall action policies' USING ERRCODE='P6063';
    END IF;
END;
$migration_606_down$;

DROP TRIGGER firewall_action_head_guard_606 ON firewall_action_policy_heads;
CREATE TRIGGER firewall_action_head_guard_174
BEFORE UPDATE OR DELETE ON firewall_action_policy_heads
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_head_174();
DROP FUNCTION guard_firewall_action_head_606();
ALTER TABLE firewall_action_policy_heads DROP COLUMN enabled;
