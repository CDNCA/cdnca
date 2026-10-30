LOCK TABLE schema_migrations, deployment_domain_event_source_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_189$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 188 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 188 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=188 AND migration_id='188_plugin_webhook_installation_binding' AND
              checksum_sha256='d3dd872b493087fb38318949831c0997ad22615177447a6fed8cf5384d3323d2' AND
              down_checksum_sha256='8ef29275c68d9f2416397bdb5d3e028dbd0b900e515e1eb13813ff8245144ecd' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=187 AND migration_id='187_deployment_domain_event_source_outbox' AND
              checksum_sha256='1d7132c342f82b1445ef0be83968704465fd26659915ecb24d2c566e082e2be4' AND
              down_checksum_sha256='cd9144e913d60826c7e5742ab02e23ad8de2905f42282376b90caee2c32a4422' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 189 requires the exact verified 188 and 187 release heads'
            USING ERRCODE='P1890';
    END IF;
END;
$migration_189$;

CREATE TABLE deployment_domain_event_fanout_receipts (
    source_id uuid NOT NULL REFERENCES deployment_domain_event_source_outbox(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL,
    installation_authorization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    plugin_id text NOT NULL CHECK (btrim(plugin_id) <> '' AND octet_length(plugin_id) <= 256),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','published','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    event_id uuid,
    delivery_id uuid,
    error text CHECK (error IS NULL OR char_length(error) <= 2048),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (source_id, subscription_id),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT,
    CHECK ((status='pending' AND completed_at IS NULL AND error IS NULL AND event_id IS NULL AND delivery_id IS NULL) OR
           (status='published' AND completed_at IS NOT NULL AND error IS NULL AND event_id IS NOT NULL AND delivery_id IS NOT NULL) OR
           (status='failed' AND completed_at IS NOT NULL AND error IS NOT NULL AND char_length(btrim(error)) > 0 AND event_id IS NULL AND delivery_id IS NULL)),
    CHECK ((event_id IS NULL) = (delivery_id IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX deployment_domain_event_fanout_receipts_pending_idx
    ON deployment_domain_event_fanout_receipts(source_id, subscription_id)
    WHERE status='pending';

CREATE INDEX deployment_domain_event_fanout_receipts_subscription_idx
    ON deployment_domain_event_fanout_receipts(tenant_scope_id, subscription_id, created_at DESC);

CREATE FUNCTION validate_deployment_domain_event_fanout_receipt_189()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' AND
       ROW(NEW.source_id,NEW.tenant_scope_id,NEW.subscription_id,NEW.installation_authorization_id,
           NEW.installation_id,NEW.plugin_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.source_id,OLD.tenant_scope_id,OLD.subscription_id,OLD.installation_authorization_id,
           OLD.installation_id,OLD.plugin_id,OLD.created_at) THEN
        RAISE EXCEPTION 'deployment fanout receipt identity is immutable' USING ERRCODE='P1891';
    END IF;
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'deployment fanout receipts are append-only' USING ERRCODE='P1892';
    END IF;
    IF TG_OP='UPDATE' AND OLD.status IN ('published','failed') AND
       ROW(NEW.status,NEW.attempts,NEW.event_id,NEW.delivery_id,NEW.error,NEW.completed_at) IS DISTINCT FROM
       ROW(OLD.status,OLD.attempts,OLD.event_id,OLD.delivery_id,OLD.error,OLD.completed_at) THEN
        RAISE EXCEPTION 'deployment fanout receipt terminal state is immutable' USING ERRCODE='P1895';
    END IF;
    IF TG_OP='UPDATE' AND NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION 'deployment fanout receipt attempts cannot decrease' USING ERRCODE='P1896';
    END IF;
    IF NEW.status='pending' AND NEW.attempts < 0 THEN
        RAISE EXCEPTION 'deployment fanout receipt attempts are invalid' USING ERRCODE='P1893';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189
BEFORE INSERT OR UPDATE OR DELETE ON deployment_domain_event_fanout_receipts
FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();

REVOKE ALL ON FUNCTION validate_deployment_domain_event_fanout_receipt_189() FROM PUBLIC;
