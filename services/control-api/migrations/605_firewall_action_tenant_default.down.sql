-- 605 回滚：去掉防火墙动作租户默认与站点继承修订。已有租户默认或继承修订时拒绝回滚（不静默丢策略事实）。
LOCK TABLE schema_migrations, firewall_action_policy_heads, firewall_action_policy_revisions,
    firewall_action_tenant_defaults, firewall_action_tenant_default_revisions,
    firewall_action_tenant_default_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_605_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 605 OR
       (SELECT max(version) FROM schema_migrations) <> 605 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=605 AND
        migration_id='605_firewall_action_tenant_default' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 605 down requires the exact verified migration head' USING ERRCODE='P6053';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_action_tenant_default_revisions) OR
       EXISTS (SELECT 1 FROM firewall_action_tenant_default_receipts) OR
       EXISTS (SELECT 1 FROM firewall_action_policy_revisions WHERE inherited) THEN
        RAISE EXCEPTION 'migration 605 down would discard firewall action default facts' USING ERRCODE='P6054';
    END IF;
END;
$migration_605_down$;

DROP TRIGGER firewall_action_outbox_inherited_605 ON firewall_action_publication_outbox;
DROP FUNCTION guard_firewall_action_inherited_outbox_605();
ALTER TABLE firewall_action_policy_heads
    DROP CONSTRAINT firewall_action_policy_heads_inherited_revision_605,
    DROP CONSTRAINT firewall_action_policy_heads_inherited_605,
    DROP COLUMN inherited;
ALTER TABLE firewall_action_policy_revisions
    DROP CONSTRAINT firewall_action_policy_revisions_inherited_key_605,
    DROP CONSTRAINT firewall_action_policy_revisions_inherited_605,
    DROP COLUMN inherited;
DROP TRIGGER firewall_action_tenant_default_receipts_no_truncate_605 ON firewall_action_tenant_default_receipts;
DROP TRIGGER firewall_action_tenant_default_revisions_no_truncate_605 ON firewall_action_tenant_default_revisions;
DROP TRIGGER firewall_action_tenant_defaults_no_truncate_605 ON firewall_action_tenant_defaults;
DROP TRIGGER firewall_action_tenant_default_receipts_immutable_605 ON firewall_action_tenant_default_receipts;
DROP TRIGGER firewall_action_tenant_default_revisions_immutable_605 ON firewall_action_tenant_default_revisions;
DROP TRIGGER firewall_action_tenant_defaults_guard_605 ON firewall_action_tenant_defaults;
DROP FUNCTION guard_firewall_action_tenant_default_605();
DROP TABLE firewall_action_tenant_default_receipts;
ALTER TABLE firewall_action_tenant_defaults DROP CONSTRAINT firewall_action_tenant_defaults_current_revision_605;
DROP TABLE firewall_action_tenant_default_revisions;
DROP TABLE firewall_action_tenant_defaults;
