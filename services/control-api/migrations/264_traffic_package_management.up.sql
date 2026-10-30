LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
DO $migration_264_up_head$
BEGIN
 IF (SELECT count(*) FROM schema_migrations) <> 263 OR
    (SELECT min(version) FROM schema_migrations) <> 1 OR
    (SELECT max(version) FROM schema_migrations) <> 263 OR
    NOT EXISTS (
      SELECT 1 FROM schema_migrations
      WHERE version=263 AND migration_id='263_package_addon_management'
        AND checksum_sha256='605cdaf423be1fdb8ffcf2c7a6a57131bfd5fc19e1a74bd925faa312eb539fc1'
        AND down_checksum_sha256='0f89c223acc10db6e0a869aab0f233e11c24df5ea5d2d32c6083328dae69094d'
        AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
  RAISE EXCEPTION 'migration 264 requires the exact verified 263 release head' USING ERRCODE='P2640';
 END IF;
END;
$migration_264_up_head$;
ALTER TABLE traffic_package_product_snapshots
 ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (octet_length(remark) <= 1024),
 ADD COLUMN allowed_package_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_package_ids) <= 100);

CREATE TABLE traffic_package_management_facts (
 id uuid PRIMARY KEY,
 target_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN ('archive_product','enable_grant','disable_grant')),
 revision bigint NOT NULL CHECK(revision>0),
 actor_user_id uuid NOT NULL REFERENCES users(id),
 actor_scope_id uuid NOT NULL REFERENCES access_scopes(id),
 idempotency_key text NOT NULL CHECK(octet_length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 request_id text NOT NULL,
 trace_id text NOT NULL,
 occurred_at timestamptz NOT NULL,
 UNIQUE(actor_user_id,idempotency_key),
 UNIQUE(target_id,revision),
 FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id)
);
CREATE INDEX traffic_package_management_latest ON traffic_package_management_facts(target_id,revision DESC);
CREATE TRIGGER traffic_package_management_immutable BEFORE UPDATE OR DELETE ON traffic_package_management_facts
 FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_management_no_truncate BEFORE TRUNCATE ON traffic_package_management_facts
 FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE FUNCTION validate_traffic_package_management_fact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.operation='archive_product' THEN
  IF NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM traffic_package_product_snapshots WHERE product_id=NEW.target_id) THEN
   RAISE EXCEPTION 'invalid archived traffic product';
  END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM traffic_package_grants WHERE id=NEW.target_id) OR
     NEW.revision<>COALESCE((SELECT max(revision) FROM traffic_package_management_facts WHERE target_id=NEW.target_id),0)+1 THEN
   RAISE EXCEPTION 'invalid traffic grant lifecycle';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER traffic_package_management_validate BEFORE INSERT ON traffic_package_management_facts
 FOR EACH ROW EXECUTE FUNCTION validate_traffic_package_management_fact();
CREATE FUNCTION require_traffic_package_management_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM audit_events WHERE action='traffic_package.'||NEW.operation AND
  resource_type='traffic_package_management' AND resource_id=NEW.target_id::text AND
  actor_user_id=NEW.actor_user_id AND scope_id=NEW.actor_scope_id AND request_id=NEW.request_id AND
  result='success' AND payload->>'fact_id'=NEW.id::text) THEN
  RAISE EXCEPTION 'traffic package management audit is missing';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER traffic_package_management_audited AFTER INSERT ON traffic_package_management_facts
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_traffic_package_management_audit();
GRANT SELECT, INSERT ON traffic_package_management_facts TO cdnca_control_app,cdnca_control_runtime;

CREATE FUNCTION require_traffic_product_management() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE product traffic_package_product_snapshots%ROWTYPE;
BEGIN
 SELECT * INTO product FROM traffic_package_product_snapshots WHERE id=NEW.product_snapshot_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('traffic_package_product_lifecycle:'||product.product_id::text,0));
 IF EXISTS(SELECT 1 FROM traffic_package_management_facts WHERE target_id=product.product_id AND operation='archive_product') THEN
  RAISE EXCEPTION 'traffic product has been archived';
 END IF;
 IF cardinality(product.allowed_package_ids)>0 AND NOT EXISTS (
  SELECT 1 FROM package_subscriptions subscription
  JOIN LATERAL (SELECT * FROM package_subscription_entitlement_versions v WHERE v.subscription_id=subscription.id AND
   v.effective_at<=NEW.starts_at ORDER BY v.effective_at DESC,v.revision DESC LIMIT 1) entitlement ON true
  WHERE subscription.tenant_scope_id=NEW.tenant_scope_id AND subscription.lifecycle_status='active' AND
   subscription.starts_at<=NEW.starts_at AND subscription.ends_at>NEW.starts_at AND
   entitlement.entitlement_status='active' AND (entitlement.effective_until IS NULL OR entitlement.effective_until>NEW.starts_at) AND
   entitlement.product_id=ANY(product.allowed_package_ids) AND
   (NEW.commerce_order_id IS NULL OR subscription.created_by_user_id=(SELECT user_id FROM package_orders WHERE id=NEW.commerce_order_id))
 ) THEN RAISE EXCEPTION 'traffic package requires an eligible base package'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER traffic_package_grants_management BEFORE INSERT ON traffic_package_grants
 FOR EACH ROW EXECUTE FUNCTION require_traffic_product_management();
