LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 262 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 262 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 262 AND migration_id = '262_package_sold_cname_authority' AND
              checksum_sha256 = '78c978b9a33a5a91aebc7bd6593221fc259dd8789bf7a2c73f4352ed5fd393d0' AND
              down_checksum_sha256 = 'a48d8ab3fbc6c1fdc12a02599ebb1c21237bd56ed21526597e1f4aefd0de30b8' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 263 requires the exact verified 262 release head'
            USING ERRCODE = 'P2630';
    END IF;
END;
$$;

CREATE TABLE package_addon_products (
    id uuid PRIMARY KEY,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    remark text NOT NULL DEFAULT '' CHECK (char_length(remark) <= 512),
    kind text NOT NULL CHECK (kind IN ('traffic','domains','root_domains','http_ports','stream_ports','custom_cc','waf')),
    quantity bigint NOT NULL CHECK (quantity BETWEEN 1 AND 1000000000),
    monthly_price_minor bigint NOT NULL CHECK (monthly_price_minor BETWEEN 0 AND 1000000000000),
    product_ids uuid[] NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CHECK (kind <> 'waf' OR quantity = 1),
    CHECK (cardinality(product_ids) <= 100 AND updated_at >= created_at)
);
CREATE UNIQUE INDEX package_addon_name_active ON package_addon_products(lower(name)) WHERE deleted_at IS NULL;

CREATE FUNCTION protect_package_addon_product() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'retain addon product history'; END IF;
 IF OLD.deleted_at IS NOT NULL OR NEW.revision<>OLD.revision+1 OR
  ROW(NEW.id,NEW.display_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.display_id,OLD.created_at) THEN
  RAISE EXCEPTION 'immutable addon product identity and revision';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER package_addon_product_guard BEFORE UPDATE OR DELETE ON package_addon_products FOR EACH ROW EXECUTE FUNCTION protect_package_addon_product();
CREATE TRIGGER package_addon_product_no_truncate BEFORE TRUNCATE ON package_addon_products FOR EACH STATEMENT EXECUTE FUNCTION protect_package_addon_product();

CREATE TABLE package_addon_assignments (
    id uuid PRIMARY KEY,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    addon_id uuid NOT NULL REFERENCES package_addon_products(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('traffic','domains','root_domains','http_ports','stream_ports','custom_cc','waf')),
    amount bigint NOT NULL CHECK (amount BETWEEN 1 AND 1000000),
    snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    charged_minor bigint NOT NULL DEFAULT 0 CHECK (charged_minor = 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (kind <> 'waf' OR amount = 1),
    CHECK (updated_at >= created_at),
    FOREIGN KEY (tenant_scope_id, owner_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX package_addon_assignment_active ON package_addon_assignments(addon_id,subscription_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX package_addon_waf_active ON package_addon_assignments(subscription_id) WHERE revoked_at IS NULL AND kind='waf';
CREATE INDEX package_addon_assignment_subscription ON package_addon_assignments(subscription_id) WHERE revoked_at IS NULL;

CREATE FUNCTION protect_package_addon_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'retain addon assignment history'; END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 OR
       ROW(NEW.id,NEW.display_id,NEW.addon_id,NEW.tenant_scope_id,NEW.owner_user_id,NEW.subscription_id,NEW.kind,NEW.snapshot,NEW.charged_minor,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.display_id,OLD.addon_id,OLD.tenant_scope_id,OLD.owner_user_id,OLD.subscription_id,OLD.kind,OLD.snapshot,OLD.charged_minor,OLD.created_at) THEN
        RAISE EXCEPTION 'immutable addon assignment identity and snapshot';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER package_addon_assignment_guard BEFORE UPDATE OR DELETE ON package_addon_assignments FOR EACH ROW EXECUTE FUNCTION protect_package_addon_assignment();
CREATE TRIGGER package_addon_assignment_no_truncate BEFORE TRUNCATE ON package_addon_assignments FOR EACH STATEMENT EXECUTE FUNCTION protect_package_addon_assignment();

CREATE FUNCTION require_package_addon_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM audit_events e WHERE e.resource_type='package_addon' AND e.resource_id=NEW.id::text
        AND e.action LIKE 'package.addon.%' AND (e.payload->>'revision')::bigint=NEW.revision AND e.result='success') THEN
        RAISE EXCEPTION 'addon mutation requires an audit fact';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER package_addon_products_audited AFTER INSERT OR UPDATE ON package_addon_products DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_package_addon_audit();
CREATE CONSTRAINT TRIGGER package_addon_assignments_audited AFTER INSERT OR UPDATE ON package_addon_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_package_addon_audit();

CREATE TABLE package_addon_write_receipts (
    actor_user_id uuid NOT NULL REFERENCES users(id),
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY(actor_user_id,actor_scope_id,idempotency_key)
);
CREATE TRIGGER package_addon_receipts_immutable BEFORE UPDATE OR DELETE ON package_addon_write_receipts
    FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();
CREATE TRIGGER package_addon_receipts_no_truncate BEFORE TRUNCATE ON package_addon_write_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_commerce_fact_mutation();

CREATE FUNCTION package_addon_effective_base_limits(p_subscription uuid, p_at timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT coalesce(coalesce(e.product_snapshot,s.product_snapshot)#>'{spec,limits}','{}'::jsonb)
 || jsonb_build_object('domains',coalesce(e.domain_limit,s.domain_limit),'monthly_traffic_bytes',coalesce(e.traffic_limit_bytes,s.traffic_limit_bytes))
 || jsonb_build_object('waf',coalesce((coalesce(e.product_snapshot,s.product_snapshot)#>>'{spec,protection,waf}')::boolean,false))
 FROM package_subscriptions s LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id
 AND e.revision=package_subscription_effective_entitlement_revision(s.id,p_at) WHERE s.id=p_subscription;
$$;
REVOKE ALL ON FUNCTION package_addon_effective_base_limits(uuid,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION package_addon_effective_base_limits(uuid,timestamptz) TO cdnca_control_app;

CREATE FUNCTION package_addon_effective_limits(p_subscription uuid, p_at timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    WITH base AS (
        SELECT package_addon_effective_base_limits(s.id,p_at) AS limits
        FROM package_subscriptions s
        LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id
          AND e.revision=package_subscription_effective_entitlement_revision(s.id,p_at)
        WHERE s.id=p_subscription
    ), increments AS (
        SELECT kind,sum((snapshot->>'quantity')::numeric*amount*CASE WHEN kind='traffic' THEN 1073741824 ELSE 1 END) AS quantity
        FROM package_addon_assignments a JOIN package_subscriptions s ON s.id=a.subscription_id
        WHERE a.subscription_id=p_subscription AND a.revoked_at IS NULL
          AND s.lifecycle_status='active' AND s.starts_at<=p_at AND s.ends_at>p_at
        GROUP BY kind
    ), keys AS (
        SELECT * FROM (VALUES ('traffic','monthly_traffic_bytes'),('domains','domains'),
          ('root_domains','root_domains'),('http_ports','http_ports'),('stream_ports','stream_ports'),
          ('custom_cc','custom_cc'),('waf','waf')) AS k(kind,key)
    )
    SELECT coalesce((SELECT limits FROM base),'{}'::jsonb) || coalesce(jsonb_object_agg(key,
        CASE WHEN keys.kind IN ('custom_cc','waf') THEN to_jsonb(coalesce((base.limits->>key)::boolean,false) OR coalesce(increments.quantity,0)>0)
             WHEN coalesce((base.limits->>key)::numeric,0)=-1 THEN '-1'::jsonb
             ELSE to_jsonb(coalesce((base.limits->>key)::numeric,0)+coalesce(increments.quantity,0)) END),'{}'::jsonb)
    FROM keys LEFT JOIN increments USING(kind) LEFT JOIN base ON true;
$$;
REVOKE ALL ON package_addon_products,package_addon_assignments,package_addon_write_receipts FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON package_addon_products,package_addon_assignments TO cdnca_control_app;
GRANT SELECT,INSERT ON package_addon_write_receipts TO cdnca_control_app;
GRANT USAGE,SELECT ON SEQUENCE package_addon_products_display_id_seq,package_addon_assignments_display_id_seq TO cdnca_control_app;
REVOKE ALL ON FUNCTION package_addon_effective_limits(uuid,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION package_addon_effective_limits(uuid,timestamptz) TO cdnca_control_app;

-- Failed commands are terminal facts that the permission-revocation worker may
-- cancel. Keep that transition legal without weakening any other outbox edge.
DROP TRIGGER edge_command_outbox_state_172 ON edge_command_outbox;
DROP FUNCTION enforce_edge_outbox_state_172();
CREATE FUNCTION enforce_edge_outbox_state_172()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('pending', 'failed') AND NEW.status = 'publishing' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'pending' AND NEW.status IN ('cancelled', 'held') THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'failed' AND NEW.status = 'cancelled' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'held' AND NEW.status IN ('pending', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'publishing' AND NEW.status IN ('published', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE = 'P1725';
END;
$$;
CREATE TRIGGER edge_command_outbox_state_172 BEFORE UPDATE OF status ON edge_command_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_edge_outbox_state_172();
