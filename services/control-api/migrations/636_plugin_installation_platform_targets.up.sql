-- 636（插件由主控平台管理员确认安装；前驱 635_market_ban_sync，守卫钉前驱 migration_id）：
-- 租户级插件（页面插件、外部服务）也由主控平台管理员确认安装，
-- 确认时选装到哪些租户（全部租户 / 指定租户），之后这些租户直接可用，租户不再确认。
--
--   1. 平台作用域可以持有 resource_scope='tenant' 的 head（585 守卫放宽这一种组合；平台插件仍只在平台作用域）。
--      一个市场授权仍只有一个本地 head（586 唯一索引不变），生命周期、回执、授权端回报都不变。
--   2. plugin_installation_targets：平台持有的租户插件装给谁。all_tenants=true 覆盖全部租户（含以后新建的），
--      否则只覆盖 plugin_installation_target_tenants 里的租户作用域。revision 供 If-Match；
--      last_idempotency_key/last_request_sha256 让同一次改动的重试原样回放。
--      平台持有的租户 head 必须有目标行（提交时检查，P6362）。
--   3. plugin_installation_covers_tenant_636(authorization, tenant scope)：租户直接持有的 head（1.0.35 之前租户自己
--      确认的）只覆盖它自己；平台持有的按目标判定。
--   4. 插件身份 API Key（604）、Webhook 订阅（188）、事件扇出回执（368）原来按 (租户作用域, 授权) 复合外键指向
--      head，改为按授权外键（586 唯一索引）+ 触发器按覆盖判定：被覆盖的租户能给插件签身份、建订阅、收事件；
--      从目标里移除的租户，已签的身份下次鉴权即失效（internal/apikey、apikeycredential 同样按覆盖判定）。
-- 不新增权限码：确认与改目标都要平台已有的 plugin_installations.platform.manage（585，只授 platform_owner）。
LOCK TABLE schema_migrations, plugin_installation_heads, api_keys, plugin_webhook_subscriptions,
    domain_event_fanout_receipts_368 IN ACCESS EXCLUSIVE MODE;

DO $migration_636_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 635 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 635 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=635 AND
        migration_id='635_market_ban_sync' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.validate_plugin_installation_resource_scope_585()') IS NULL OR
          to_regclass(current_schema() || '.plugin_installation_targets') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 636 requires the exact verified 635 release head' USING ERRCODE='P6360';
    END IF;
END;
$migration_636_up$;

CREATE OR REPLACE FUNCTION validate_plugin_installation_resource_scope_585()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.resource_scope IS DISTINCT FROM OLD.resource_scope THEN
        RAISE EXCEPTION 'plugin installation resource scope is immutable' USING ERRCODE='P5851';
    END IF;
    -- 636: the controller's platform scope may also hold a tenant plugin it confirmed for chosen tenants.
    IF NOT EXISTS (SELECT 1 FROM access_scopes scope
                   WHERE scope.id=NEW.tenant_scope_id AND
                         (scope.kind=NEW.resource_scope OR (scope.kind='platform' AND NEW.resource_scope='tenant'))) THEN
        RAISE EXCEPTION 'plugin installation resource scope does not match its access scope' USING ERRCODE='P5852';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE plugin_installation_targets (
    authorization_id uuid PRIMARY KEY REFERENCES plugin_installation_heads(authorization_id) ON DELETE RESTRICT,
    all_tenants boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    last_idempotency_key text NOT NULL CHECK (last_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    last_request_sha256 bytea NOT NULL CHECK (octet_length(last_request_sha256) = 32),
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE TABLE plugin_installation_target_tenants (
    authorization_id uuid NOT NULL REFERENCES plugin_installation_targets(authorization_id) ON DELETE CASCADE,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (authorization_id, tenant_scope_id)
);
CREATE INDEX plugin_installation_target_tenants_tenant_636_idx
    ON plugin_installation_target_tenants(tenant_scope_id, authorization_id);

-- Targets only belong to a platform-held tenant plugin; listed targets are tenant scopes.
CREATE FUNCTION validate_plugin_installation_target_636()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME='plugin_installation_targets' THEN
        IF TG_OP='UPDATE' AND NEW.authorization_id IS DISTINCT FROM OLD.authorization_id THEN
            RAISE EXCEPTION 'plugin installation target authorization is immutable' USING ERRCODE='P6361';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM plugin_installation_heads head
                       JOIN access_scopes scope ON scope.id=head.tenant_scope_id AND scope.kind='platform'
                       WHERE head.authorization_id=NEW.authorization_id AND head.resource_scope='tenant') THEN
            RAISE EXCEPTION 'plugin installation targets need a platform-held tenant plugin' USING ERRCODE='P6361';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM access_scopes scope WHERE scope.id=NEW.tenant_scope_id AND scope.kind='tenant') THEN
        RAISE EXCEPTION 'plugin installation target is not a tenant scope' USING ERRCODE='P6361';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER plugin_installation_targets_636
BEFORE INSERT OR UPDATE ON plugin_installation_targets
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_target_636();
CREATE TRIGGER plugin_installation_target_tenants_636
BEFORE INSERT OR UPDATE ON plugin_installation_target_tenants
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_target_636();

-- A platform-held tenant plugin is never left without targets (checked at commit: head and targets are written
-- in the same transaction).
CREATE FUNCTION require_plugin_installation_targets_636()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.resource_scope='tenant' AND
       EXISTS (SELECT 1 FROM access_scopes scope WHERE scope.id=NEW.tenant_scope_id AND scope.kind='platform') AND
       NOT EXISTS (SELECT 1 FROM plugin_installation_targets target WHERE target.authorization_id=NEW.authorization_id) THEN
        RAISE EXCEPTION 'platform-held tenant plugin installation has no targets' USING ERRCODE='P6362';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER plugin_installation_heads_targets_636
AFTER INSERT ON plugin_installation_heads DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_plugin_installation_targets_636();

CREATE FUNCTION plugin_installation_covers_tenant_636(checked_authorization_id uuid, checked_tenant_scope_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM plugin_installation_heads head
        JOIN access_scopes holder ON holder.id=head.tenant_scope_id
        WHERE head.authorization_id=checked_authorization_id AND head.resource_scope='tenant' AND (
            (holder.kind='tenant' AND head.tenant_scope_id=checked_tenant_scope_id) OR
            (holder.kind='platform' AND EXISTS (
                SELECT 1 FROM plugin_installation_targets target
                JOIN access_scopes tenant ON tenant.id=checked_tenant_scope_id AND tenant.kind='tenant'
                WHERE target.authorization_id=head.authorization_id AND (target.all_tenants OR EXISTS (
                    SELECT 1 FROM plugin_installation_target_tenants listed
                    WHERE listed.authorization_id=target.authorization_id AND
                          listed.tenant_scope_id=checked_tenant_scope_id))))))
$$;

ALTER TABLE api_keys DROP CONSTRAINT api_keys_plugin_installation_604_fk,
    ADD CONSTRAINT api_keys_plugin_installation_636_fk FOREIGN KEY (plugin_installation_authorization_id)
        REFERENCES plugin_installation_heads(authorization_id) ON DELETE RESTRICT;
ALTER TABLE plugin_webhook_subscriptions DROP CONSTRAINT plugin_webhook_subscriptions_installation_binding_188_fk,
    ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_636_fk FOREIGN KEY (installation_authorization_id)
        REFERENCES plugin_installation_heads(authorization_id) ON DELETE RESTRICT;
DO $migration_636_fanout_fk$
DECLARE
    constraint_name text;
BEGIN
    SELECT con.conname INTO constraint_name
    FROM pg_constraint con
    WHERE con.conrelid='domain_event_fanout_receipts_368'::regclass AND con.contype='f' AND
          con.confrelid='plugin_installation_heads'::regclass;
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'migration 636 cannot find the fanout receipt installation key' USING ERRCODE='P6363';
    END IF;
    EXECUTE format('ALTER TABLE domain_event_fanout_receipts_368 DROP CONSTRAINT %I', constraint_name);
END;
$migration_636_fanout_fk$;
ALTER TABLE domain_event_fanout_receipts_368
    ADD CONSTRAINT domain_event_fanout_receipts_installation_636_fk FOREIGN KEY (installation_authorization_id)
        REFERENCES plugin_installation_heads(authorization_id) ON DELETE RESTRICT;

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
    WHERE head.authorization_id=NEW.plugin_installation_authorization_id AND
          plugin_installation_covers_tenant_636(head.authorization_id, NEW.scope_id)
    FOR SHARE;
    IF NOT FOUND OR head_status IS DISTINCT FROM 'enabled' OR
       head_installation_id IS DISTINCT FROM NEW.plugin_installation_id OR
       head_plugin_id IS DISTINCT FROM NEW.plugin_id THEN
        RAISE EXCEPTION 'API key plugin binding is not an enabled installation of this tenant' USING ERRCODE='P6042';
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
    WHERE head.authorization_id=NEW.installation_authorization_id AND
          plugin_installation_covers_tenant_636(head.authorization_id, NEW.tenant_scope_id)
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
          ON installation.authorization_id=subscription.installation_authorization_id
         AND plugin_installation_covers_tenant_636(installation.authorization_id, subscription.tenant_scope_id)
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
