LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_188$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 187 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 187 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=187 AND migration_id='187_deployment_domain_event_source_outbox' AND
              checksum_sha256='1d7132c342f82b1445ef0be83968704465fd26659915ecb24d2c566e082e2be4' AND
              down_checksum_sha256='cd9144e913d60826c7e5742ab02e23ad8de2905f42282376b90caee2c32a4422' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 188 requires the exact verified 187 release head'
            USING ERRCODE='P1880';
    END IF;
END;
$migration_188$;

LOCK TABLE plugin_webhook_subscriptions, plugin_installation_heads IN ACCESS EXCLUSIVE MODE;

ALTER TABLE plugin_webhook_subscriptions
    ADD COLUMN installation_authorization_id uuid,
    ADD COLUMN installation_id uuid,
    ADD COLUMN plugin_id text;

ALTER TABLE plugin_webhook_subscriptions
    ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_shape_188
        CHECK ((installation_authorization_id IS NULL AND installation_id IS NULL AND plugin_id IS NULL) OR
               (installation_authorization_id IS NOT NULL AND installation_id IS NOT NULL AND plugin_id IS NOT NULL)),
    ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_188_fk
        FOREIGN KEY (tenant_scope_id, installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id)
        ON DELETE RESTRICT;

CREATE INDEX plugin_webhook_subscriptions_installation_binding_188_idx
    ON plugin_webhook_subscriptions(tenant_scope_id, installation_authorization_id)
    WHERE installation_authorization_id IS NOT NULL;

CREATE FUNCTION validate_plugin_webhook_installation_binding_188()
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

CREATE TRIGGER plugin_webhook_subscriptions_installation_binding_188
BEFORE INSERT OR UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_installation_binding_188();

REVOKE ALL ON FUNCTION validate_plugin_webhook_installation_binding_188() FROM PUBLIC;
