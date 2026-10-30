LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_370_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 369 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 369 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=369 AND
        migration_id='369_domain_event_producers' AND
        checksum_sha256='aee6a30a6111fd2bbdb0ed68bf42f8b398c3868bbab1b57be259784c132911a9' AND
        down_checksum_sha256='683e9da03180b13aa62a64099ee190b29e58cf03bd5d14321896bf48029b30f7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 370 requires the exact verified 369 release head' USING ERRCODE='P3700';
    END IF;
END;
$migration_370_up$;

-- PA-24 subscription filter: a subscription may name the sites it wants.
-- NULL = every site and every tenant-level event. A non-empty list = only
-- site-bound events (site.updated, security.incident_detected) of those
-- sites; tenant-level events (deployment, certificate, node, usage) are not
-- delivered to it. The filter is part of the immutable subscription identity
-- (change it by creating a new subscription and revoking the old one).
LOCK TABLE plugin_webhook_subscriptions, plugin_webhook_deliveries IN ACCESS EXCLUSIVE MODE;

ALTER TABLE plugin_webhook_subscriptions
    ADD COLUMN site_ids uuid[],
    ADD CONSTRAINT plugin_webhook_subscriptions_site_ids_370 CHECK (
        site_ids IS NULL OR (cardinality(site_ids) BETWEEN 1 AND 100 AND array_position(site_ids, NULL) IS NULL)
    );

CREATE FUNCTION validate_plugin_webhook_site_filter_370()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.site_ids IS DISTINCT FROM OLD.site_ids THEN
            RAISE EXCEPTION 'plugin webhook site filter is immutable' USING ERRCODE='P3701';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.site_ids IS NULL THEN
        RETURN NEW;
    END IF;
    IF cardinality(NEW.site_ids) <> (SELECT count(DISTINCT value) FROM unnest(NEW.site_ids) AS value) THEN
        RAISE EXCEPTION 'plugin webhook site filter repeats a site' USING ERRCODE='P3701';
    END IF;
    IF NEW.event_types = ARRAY['io.cdnca.webhook.v1.test']::text[] OR NOT EXISTS (
        SELECT 1 FROM unnest(NEW.event_types) AS requested(event_type)
        JOIN domain_event_types_368 contract ON contract.event_type=requested.event_type AND contract.site_bound) THEN
        RAISE EXCEPTION 'plugin webhook site filter needs a site-bound event type' USING ERRCODE='P3701';
    END IF;
    IF (SELECT count(*) FROM sites site
        WHERE site.id = ANY(NEW.site_ids) AND site.scope_id=NEW.tenant_scope_id AND site.deleted_at IS NULL)
       <> cardinality(NEW.site_ids) THEN
        RAISE EXCEPTION 'plugin webhook site filter names a site outside the tenant' USING ERRCODE='P3702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_subscriptions_site_filter_370
BEFORE INSERT OR UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_site_filter_370();

-- Replays re-check the filter as well as the permission (368): a delivery of
-- a site-bound event must name a site the subscription still selects.
CREATE FUNCTION validate_plugin_webhook_delivery_site_370()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    selected uuid[];
    event_site text;
BEGIN
    SELECT subscription.site_ids INTO selected FROM plugin_webhook_subscriptions subscription
    WHERE subscription.tenant_scope_id=NEW.tenant_scope_id AND subscription.id=NEW.subscription_id;
    IF selected IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT event.data->>'site_id' INTO event_site FROM plugin_webhook_events event
    JOIN domain_event_types_368 contract ON contract.event_type=event.event_type AND contract.site_bound
    WHERE event.tenant_scope_id=NEW.tenant_scope_id AND event.subscription_id=NEW.subscription_id
      AND event.id=NEW.event_id;
    IF event_site IS NULL OR NOT (event_site::uuid = ANY(selected)) THEN
        RAISE EXCEPTION 'plugin webhook delivery is outside the subscription site filter' USING ERRCODE='P3687';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_deliveries_site_filter_370
BEFORE INSERT ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_delivery_site_370();

REVOKE ALL ON FUNCTION validate_plugin_webhook_site_filter_370(), validate_plugin_webhook_delivery_site_370() FROM PUBLIC;
