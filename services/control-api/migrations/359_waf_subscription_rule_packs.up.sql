LOCK TABLE schema_migrations, waf_rule_subscriptions, rule_packs, rule_pack_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_359_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 358 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 358 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=358 AND
        migration_id='358_node_artifact_sets' AND
        checksum_sha256='67cd69e1463ce32abf89a6dc2182185806cb260f283a31797bb8997d78831d5b' AND
        down_checksum_sha256='6f3c098dc885ef7709d05361c8c73046e4077274f3110aebe6920b6d523de94b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.waf_rule_subscription_packs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 359 requires the exact verified 358 release head' USING ERRCODE='P3590';
    END IF;
END;
$migration_359_up$;

-- r136 PA-25 (placeholder number; renumbered on merge): a WAF rule
-- subscription no longer feeds "@system/<id>" policy copies. A tenant that
-- subscribes gets its own user layer rule pack (user/<tenant>/waf-sub-...);
-- every fetch whose rules changed adds a new version of each subscriber's
-- pack (rule_pack_artifacts.source = 'subscription'). The pack is downloaded,
-- never enabled by the subscription; sites mounting it show "待发布" until
-- they are published again. waf_rule_subscriptions.rules now holds the
-- compiled rule pack rules of the last good snapshot.
ALTER TABLE rule_pack_artifacts DROP CONSTRAINT rule_pack_artifacts_source_check;
ALTER TABLE rule_pack_artifacts ADD CONSTRAINT rule_pack_artifacts_source_359
    CHECK (source IN ('catalog', 'import', 'tenant', 'subscription'));

-- waf_rule_subscription_packs: one row per (subscription, subscribing
-- tenant). Deleting the pack (its last version) ends the subscription;
-- unsubscribing removes only this row and keeps the pack.
CREATE TABLE waf_rule_subscription_packs (
    subscription_id uuid NOT NULL REFERENCES waf_rule_subscriptions(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    pack_id text NOT NULL UNIQUE REFERENCES rule_packs(pack_id) ON DELETE CASCADE,
    subscribed_by_user_id uuid NOT NULL REFERENCES users(id),
    subscribed_at timestamptz NOT NULL,
    PRIMARY KEY (subscription_id, tenant_scope_id),
    CHECK (pack_id LIKE 'user/' || tenant_scope_id::text || '/waf-sub-%')
);
CREATE INDEX waf_rule_subscription_packs_tenant_359_idx ON waf_rule_subscription_packs (tenant_scope_id);

GRANT SELECT, INSERT, DELETE ON waf_rule_subscription_packs TO cdnca_control_app;
GRANT SELECT ON waf_rule_subscription_packs TO cdnca_control_runtime;
