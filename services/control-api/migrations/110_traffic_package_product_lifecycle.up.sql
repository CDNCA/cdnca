LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 109 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 109 OR
       NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=109 AND migration_id='109_site_origin_route_control'
             AND checksum_sha256='d6b3a67fa2504b048f969317c7605868ebe3ad4edf122286d546edfb023310c2'
             AND down_checksum_sha256='098fd79ed88641247b2f787b18cd170a5082c42f717b1e907491ceb6ecb61719'
             AND integrity_state='verified'
       ) THEN
        RAISE EXCEPTION 'migration 110 requires the exact verified 109 release head'
            USING ERRCODE='P1100';
    END IF;
END;
$$;

CREATE TABLE traffic_package_product_lifecycle_watermarks (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_sequence bigint NOT NULL CHECK (current_sequence >= 0)
);
INSERT INTO traffic_package_product_lifecycle_watermarks(singleton,current_sequence)
VALUES (true,0);

CREATE TABLE traffic_package_product_lifecycle_facts (
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    enabled boolean NOT NULL,
    action text NOT NULL CHECK (action IN ('baseline','enable','disable')),
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY(product_id, revision),
    UNIQUE(actor_user_id, idempotency_key),
    CHECK ((action='baseline' AND sequence=0 AND enabled) OR
           (action='enable' AND sequence>0 AND enabled) OR
           (action='disable' AND sequence>0 AND NOT enabled)),
    FOREIGN KEY(product_id, product_revision)
        REFERENCES traffic_package_product_snapshots(product_id, revision)
        ON DELETE RESTRICT,
    FOREIGN KEY(actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX traffic_package_product_lifecycle_sequence_110
    ON traffic_package_product_lifecycle_facts(sequence) WHERE sequence > 0;

LOCK TABLE traffic_package_product_snapshots,
    traffic_package_product_lifecycle_facts,
    traffic_package_product_lifecycle_watermarks
IN ACCESS EXCLUSIVE MODE;

INSERT INTO traffic_package_product_lifecycle_facts(
    product_id,product_revision,revision,sequence,enabled,action,
    actor_scope_id,actor_user_id,idempotency_key,request_digest,request_id,trace_id,occurred_at
)
SELECT snapshot.product_id, snapshot.revision, 1, 0, true, 'baseline',
       snapshot.actor_scope_id, snapshot.actor_user_id,
       'migration-110-baseline-' || snapshot.product_id::text,
       snapshot.request_digest, snapshot.request_id, snapshot.trace_id, snapshot.created_at
FROM traffic_package_product_snapshots snapshot
WHERE snapshot.revision=1;

DO $$
BEGIN
    IF (SELECT count(*) FROM traffic_package_product_lifecycle_facts) <>
       (SELECT count(DISTINCT product_id) FROM traffic_package_product_snapshots) THEN
        RAISE EXCEPTION 'migration 110 found a product without a baseline lifecycle fact'
            USING ERRCODE='P1101';
    END IF;
END;
$$;

CREATE FUNCTION append_traffic_package_product_lifecycle_baseline_110()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revision=1 THEN
        INSERT INTO traffic_package_product_lifecycle_facts(
            product_id,product_revision,revision,sequence,enabled,action,
            actor_scope_id,actor_user_id,idempotency_key,request_digest,request_id,trace_id,occurred_at
        ) VALUES (
            NEW.product_id,NEW.revision,1,0,true,'baseline',NEW.actor_scope_id,NEW.actor_user_id,
            'publish-baseline-' || NEW.product_id::text,NEW.request_digest,NEW.request_id,NEW.trace_id,NEW.created_at
        );
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER traffic_package_product_snapshots_lifecycle_baseline_110
AFTER INSERT ON traffic_package_product_snapshots
FOR EACH ROW EXECUTE FUNCTION append_traffic_package_product_lifecycle_baseline_110();

CREATE FUNCTION require_traffic_package_grant_enabled_product_110()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    product_enabled boolean;
BEGIN
    SELECT fact.enabled INTO product_enabled
    FROM traffic_package_product_snapshots snapshot
    JOIN LATERAL (
        SELECT enabled
        FROM traffic_package_product_lifecycle_facts lifecycle
        WHERE lifecycle.product_id=snapshot.product_id
        ORDER BY lifecycle.revision DESC LIMIT 1
    ) fact ON true
    WHERE snapshot.id=NEW.product_snapshot_id;
    IF product_enabled IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'traffic package grant product is disabled or missing lifecycle facts'
            USING ERRCODE='P1105';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER traffic_package_grants_require_enabled_product_110
BEFORE INSERT ON traffic_package_grants
FOR EACH ROW EXECUTE FUNCTION require_traffic_package_grant_enabled_product_110();

CREATE TABLE traffic_package_product_lifecycle_audit_links_110 (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
    product_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 1),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('enable','disable')),
    FOREIGN KEY(product_id,revision)
        REFERENCES traffic_package_product_lifecycle_facts(product_id,revision)
        ON DELETE RESTRICT,
    FOREIGN KEY(actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION bind_traffic_package_product_lifecycle_audit_110()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    product_value uuid;
    lifecycle_revision bigint;
    sequence_value bigint;
    enabled_value boolean;
    action_value text;
BEGIN
    IF NEW.result<>'success' OR NEW.action NOT IN
       ('traffic_package.product.enable','traffic_package.product.disable') THEN
        RETURN NEW;
    END IF;
    IF NEW.resource_type<>'traffic_package_product' OR
       NEW.resource_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
       NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'invalid traffic package lifecycle audit identity' USING ERRCODE='P1102';
    END IF;
    product_value := NEW.resource_id::uuid;
    lifecycle_revision := (NEW.payload->>'lifecycle_revision')::bigint;
    sequence_value := (NEW.payload->>'lifecycle_sequence')::bigint;
    enabled_value := (NEW.payload->>'enabled')::boolean;
    action_value := CASE WHEN enabled_value THEN 'enable' ELSE 'disable' END;
    IF NEW.action <> ('traffic_package.product.' || action_value) OR
       NEW.payload->>'lifecycle_revision' IS NULL OR sequence_value IS NULL OR
       NOT EXISTS (
           SELECT 1 FROM traffic_package_product_lifecycle_facts fact
           WHERE fact.product_id=product_value AND fact.revision=lifecycle_revision
             AND fact.sequence=sequence_value AND fact.enabled=enabled_value
             AND fact.action=action_value AND fact.actor_scope_id=NEW.scope_id
             AND fact.actor_user_id=NEW.actor_user_id
       ) THEN
        RAISE EXCEPTION 'traffic package lifecycle audit has no matching fact' USING ERRCODE='P1102';
    END IF;
    INSERT INTO traffic_package_product_lifecycle_audit_links_110(
        sequence,audit_event_id,product_id,revision,actor_scope_id,actor_user_id,action
    ) VALUES(sequence_value,NEW.id,product_value,lifecycle_revision,NEW.scope_id,
             NEW.actor_user_id,action_value);
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_events_bind_traffic_package_product_lifecycle_110
AFTER INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION bind_traffic_package_product_lifecycle_audit_110();

CREATE FUNCTION require_traffic_package_product_lifecycle_audit_110()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.sequence=0 THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM traffic_package_product_lifecycle_audit_links_110 link
        WHERE link.sequence=NEW.sequence AND link.product_id=NEW.product_id
          AND link.revision=NEW.revision AND link.actor_scope_id=NEW.actor_scope_id
          AND link.actor_user_id=NEW.actor_user_id
    ) OR NOT EXISTS (
        SELECT 1 FROM traffic_package_product_lifecycle_watermarks watermark
        WHERE watermark.singleton AND watermark.current_sequence=NEW.sequence
    ) OR NOT EXISTS (
        SELECT 1 FROM traffic_package_product_lifecycle_facts previous
        WHERE previous.product_id=NEW.product_id AND previous.revision=NEW.revision-1
          AND previous.enabled<>NEW.enabled
    ) THEN
        RAISE EXCEPTION 'traffic package lifecycle fact did not complete audit' USING ERRCODE='P1103';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER traffic_package_product_lifecycle_facts_audited_110
AFTER INSERT ON traffic_package_product_lifecycle_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_traffic_package_product_lifecycle_audit_110();

CREATE TRIGGER traffic_package_product_lifecycle_facts_append_only_110
BEFORE UPDATE OR DELETE ON traffic_package_product_lifecycle_facts
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_product_lifecycle_facts_no_truncate_110
BEFORE TRUNCATE ON traffic_package_product_lifecycle_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

DO $$
BEGIN
    IF (SELECT count(*) FROM traffic_package_product_lifecycle_facts WHERE sequence > 0) <> 0 THEN
        RAISE EXCEPTION 'migration 110 allocated lifecycle sequences during backfill' USING ERRCODE='P1104';
    END IF;
END;
$$;
