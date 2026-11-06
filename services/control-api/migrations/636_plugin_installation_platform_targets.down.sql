-- 636 回退：去掉平台为租户确认的插件目标与覆盖判定，复合外键与触发器恢复 188/368/585/604 原文。
-- 已有平台持有的租户插件时拒绝回退（回退后它们没有目标、租户也看不到，P6365）：先卸载并清理，或保留 636。
LOCK TABLE schema_migrations, plugin_installation_heads, api_keys, plugin_webhook_subscriptions,
    domain_event_fanout_receipts_368 IN ACCESS EXCLUSIVE MODE;

DO $migration_636_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 636 OR
       (SELECT max(version) FROM schema_migrations) <> 636 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=636 AND
        migration_id='636_plugin_installation_platform_targets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 636 down requires the exact verified migration head' USING ERRCODE='P6364';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_installation_heads head
               JOIN access_scopes scope ON scope.id=head.tenant_scope_id AND scope.kind='platform'
               WHERE head.resource_scope='tenant') THEN
        RAISE EXCEPTION 'migration 636 down refuses platform-held tenant plugin installations' USING ERRCODE='P6365';
    END IF;
END;
$migration_636_down$;

CREATE OR REPLACE FUNCTION validate_domain_event_delivery_scope_368()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    delivered_type text;
    required_scope text;
BEGIN
    SELECT event.event_type INTO delivered_type FROM plugin_webhook_events event
    WHERE event.tenant_scope_id=NEW.tenant_scope_id AND event.subscription_id=NEW.subscription_id
      AND event.id=NEW.event_id;
    IF delivered_type IS NULL OR delivered_type = 'io.cdnca.webhook.v1.test' THEN
        RETURN NEW;
    END IF;
    SELECT required_permission INTO required_scope FROM domain_event_types_368 WHERE event_type=delivered_type;
    IF required_scope IS NULL OR NOT EXISTS (
        SELECT 1 FROM plugin_webhook_subscriptions subscription
        JOIN plugin_installation_heads installation
          ON installation.tenant_scope_id=subscription.tenant_scope_id
         AND installation.authorization_id=subscription.installation_authorization_id
         AND installation.installation_id=subscription.installation_id
         AND installation.plugin_id=subscription.plugin_id
        WHERE subscription.tenant_scope_id=NEW.tenant_scope_id AND subscription.id=NEW.subscription_id
          AND installation.status='enabled' AND required_scope = ANY(installation.approved_scopes)
    ) THEN
        RAISE EXCEPTION 'plugin installation lacks the event permission' USING ERRCODE='P3687';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_plugin_webhook_installation_binding_188()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    approved_scopes text[];
    installation_status text;
    bound_installation_id uuid;
    bound_plugin_id text;
    event_type text;
    required_scope text;
BEGIN
    IF TG_OP = 'UPDATE' AND
       ROW(NEW.installation_authorization_id, NEW.installation_id, NEW.plugin_id) IS DISTINCT FROM
       ROW(OLD.installation_authorization_id, OLD.installation_id, OLD.plugin_id) THEN
        RAISE EXCEPTION 'plugin webhook installation binding is immutable'
            USING ERRCODE='P8404';
    END IF;

    IF NEW.event_types = ARRAY['io.cdnca.webhook.v1.test']::text[] THEN
        IF NEW.installation_authorization_id IS NOT NULL OR NEW.installation_id IS NOT NULL OR NEW.plugin_id IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook test-only subscription cannot bind an installation'
                USING ERRCODE='P8402';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.installation_authorization_id IS NULL OR NEW.installation_id IS NULL OR NEW.plugin_id IS NULL OR
       btrim(NEW.plugin_id) = '' THEN
        RAISE EXCEPTION 'plugin webhook non-test subscription requires an installation binding'
            USING ERRCODE='P8402';
    END IF;

    SELECT head.installation_id, head.plugin_id, head.approved_scopes, head.status
    INTO bound_installation_id, bound_plugin_id, approved_scopes, installation_status
    FROM plugin_installation_heads head
    WHERE head.tenant_scope_id=NEW.tenant_scope_id AND head.authorization_id=NEW.installation_authorization_id
    FOR UPDATE;
    IF NOT FOUND OR installation_status IS DISTINCT FROM 'enabled' OR
       bound_installation_id IS DISTINCT FROM NEW.installation_id OR
       bound_plugin_id IS DISTINCT FROM NEW.plugin_id THEN
        RAISE EXCEPTION 'plugin webhook installation binding is not an enabled tenant installation'
            USING ERRCODE='P8402';
    END IF;

    FOREACH event_type IN ARRAY NEW.event_types LOOP
        IF event_type = 'io.cdnca.webhook.v1.test' THEN
            CONTINUE;
        END IF;
        required_scope := CASE event_type
            WHEN 'io.cdnca.site.v1.updated' THEN 'events.site.read'
            WHEN 'io.cdnca.deployment.v1.status_changed' THEN 'events.deployment.read'
            WHEN 'io.cdnca.node.v1.status_changed' THEN 'events.node.read'
            WHEN 'io.cdnca.certificate.v1.status_changed' THEN 'events.certificate.read'
            WHEN 'io.cdnca.usage.v1.threshold_reached' THEN 'events.usage.read'
            WHEN 'io.cdnca.security.v1.incident_detected' THEN 'events.security.read'
            ELSE NULL
        END;
        IF event_type IN ('io.cdnca.dns.v1.changed','io.cdnca.dns.v1.deleted') THEN
            RAISE EXCEPTION 'dns event has no approved installation permission'
                USING ERRCODE='P8402';
        END IF;
        IF required_scope IS NULL OR NOT (required_scope = ANY(approved_scopes)) THEN
            RAISE EXCEPTION 'plugin webhook installation approved scope is insufficient'
                USING ERRCODE='P8402';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_api_key_plugin_installation_604()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    head_installation_id uuid;
    head_plugin_id text;
    head_status text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.plugin_installation_authorization_id, NEW.plugin_installation_id, NEW.plugin_id) IS DISTINCT FROM
           ROW(OLD.plugin_installation_authorization_id, OLD.plugin_installation_id, OLD.plugin_id) THEN
            RAISE EXCEPTION 'API key plugin installation binding is immutable' USING ERRCODE='P6041';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.plugin_installation_authorization_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT head.installation_id, head.plugin_id, head.status
    INTO head_installation_id, head_plugin_id, head_status
    FROM plugin_installation_heads head
    WHERE head.tenant_scope_id=NEW.scope_id AND head.authorization_id=NEW.plugin_installation_authorization_id
    FOR SHARE;
    IF NOT FOUND OR head_status IS DISTINCT FROM 'enabled' OR
       head_installation_id IS DISTINCT FROM NEW.plugin_installation_id OR
       head_plugin_id IS DISTINCT FROM NEW.plugin_id THEN
        RAISE EXCEPTION 'API key plugin binding is not an enabled installation of this tenant' USING ERRCODE='P6042';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE domain_event_fanout_receipts_368 DROP CONSTRAINT domain_event_fanout_receipts_installation_636_fk,
    ADD FOREIGN KEY (tenant_scope_id, installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT;
ALTER TABLE plugin_webhook_subscriptions DROP CONSTRAINT plugin_webhook_subscriptions_installation_binding_636_fk,
    ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_188_fk
        FOREIGN KEY (tenant_scope_id, installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT;
ALTER TABLE api_keys DROP CONSTRAINT api_keys_plugin_installation_636_fk,
    ADD CONSTRAINT api_keys_plugin_installation_604_fk
        FOREIGN KEY (scope_id, plugin_installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT;

DROP FUNCTION plugin_installation_covers_tenant_636(uuid, uuid);
DROP TRIGGER plugin_installation_heads_targets_636 ON plugin_installation_heads;
DROP FUNCTION require_plugin_installation_targets_636();
DROP TABLE plugin_installation_target_tenants;
DROP TABLE plugin_installation_targets;
DROP FUNCTION validate_plugin_installation_target_636();

CREATE OR REPLACE FUNCTION validate_plugin_installation_resource_scope_585()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.resource_scope IS DISTINCT FROM OLD.resource_scope THEN
        RAISE EXCEPTION 'plugin installation resource scope is immutable' USING ERRCODE='P5851';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM access_scopes scope
                   WHERE scope.id=NEW.tenant_scope_id AND scope.kind=NEW.resource_scope) THEN
        RAISE EXCEPTION 'plugin installation resource scope does not match its access scope' USING ERRCODE='P5852';
    END IF;
    RETURN NEW;
END;
$$;
