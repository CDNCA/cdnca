LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE package_groups,
    package_products,
    package_product_versions,
    package_catalog_write_requests
IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 89 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 89 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 89
          AND migration_id = '089_dns_reconcile_provider_mutation_claims'
          AND checksum_sha256 = 'abc482b3051e91756fa85e6805f17f477cb7500c1b686704c2ea5a8eaa433356'
          AND down_checksum_sha256 = '0489adafea3720243cd4518a15b53485fba0c7db2844803f7788d12186a2a4e9'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 090 requires the exact verified 089 release head'
            USING ERRCODE = 'P9000';
    END IF;
END;
$$;

ALTER TABLE package_catalog_write_requests
    DROP CONSTRAINT package_catalog_write_requests_operation_check;
ALTER TABLE package_catalog_write_requests
    ADD CONSTRAINT package_catalog_write_requests_operation_check CHECK (operation IN (
        'package.group.create',
        'package.group.update',
        'package.group.delete',
        'package.product.create',
        'package.product.update',
        'package.product.delete',
        'package.product.publish',
        'package.product.withdraw'
    ));

CREATE TABLE package_offer_lifecycle_lock (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton)
);
INSERT INTO package_offer_lifecycle_lock(singleton) VALUES(true);

CREATE TABLE package_catalog_commit_watermark_090 (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    high_water bigint NOT NULL DEFAULT 0 CHECK (high_water >= 0)
);
INSERT INTO package_catalog_commit_watermark_090(singleton,high_water) VALUES(true,0);

CREATE TABLE package_group_state_facts_090 (
    group_id uuid NOT NULL REFERENCES package_groups(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    visible boolean NOT NULL,
    sort_order integer NOT NULL,
    deleted boolean NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action IN (
        'baseline','package.group.create','package.group.update','package.group.delete'
    )),
    catalog_sequence bigint NOT NULL CHECK (catalog_sequence >= 0),
    PRIMARY KEY (group_id,revision),
    CHECK ((catalog_sequence=0)=(action='baseline'))
);
CREATE UNIQUE INDEX package_group_state_facts_sequence_090
    ON package_group_state_facts_090(catalog_sequence) WHERE catalog_sequence > 0;

CREATE TABLE package_product_state_facts_090 (
    product_id uuid NOT NULL REFERENCES package_products(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    enabled boolean NOT NULL,
    sort_order integer NOT NULL,
    spec jsonb NOT NULL CHECK (jsonb_typeof(spec)='object'),
    deleted boolean NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action IN (
        'baseline','package.product.create','package.product.update','package.product.delete'
    )),
    catalog_sequence bigint NOT NULL CHECK (catalog_sequence >= 0),
    PRIMARY KEY (product_id,revision),
    CHECK ((catalog_sequence=0)=(action='baseline'))
);
CREATE UNIQUE INDEX package_product_state_facts_sequence_090
    ON package_product_state_facts_090(catalog_sequence) WHERE catalog_sequence > 0;

CREATE TABLE package_catalog_audit_links_090 (
    catalog_sequence bigint PRIMARY KEY CHECK (catalog_sequence > 0),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
    fact_kind text NOT NULL CHECK (fact_kind IN ('group','product','publication')),
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL,
    resource_id uuid NOT NULL,
    resource_revision bigint NOT NULL CHECK (resource_revision > 0)
);

CREATE FUNCTION current_package_catalog_xid_090()
RETURNS xid
LANGUAGE sql
STABLE
AS $$
    SELECT backend_xid FROM pg_stat_activity WHERE pid=pg_backend_pid()
$$;

INSERT INTO package_group_state_facts_090(
    group_id,revision,name,visible,sort_order,deleted,actor_user_id,action,catalog_sequence
)
SELECT id,revision,name,visible,sort_order,deleted_at IS NOT NULL,updated_by_user_id,'baseline',0
FROM package_groups;

INSERT INTO package_product_state_facts_090(
    product_id,revision,name,enabled,sort_order,spec,deleted,actor_user_id,action,catalog_sequence
)
SELECT product.id,product.revision,product.name,product.enabled,product.sort_order,product.spec,
       product.deleted_at IS NOT NULL,product.updated_by_user_id,'baseline',0
FROM package_products product
JOIN package_product_versions version
  ON version.product_id=product.id AND version.revision=product.revision
 AND version.name=product.name AND version.enabled=product.enabled
 AND version.sort_order=product.sort_order AND version.spec=product.spec
 AND version.deleted=(product.deleted_at IS NOT NULL);

DO $$
BEGIN
    IF (SELECT count(*) FROM package_product_state_facts_090) <>
       (SELECT count(*) FROM package_products) THEN
        RAISE EXCEPTION 'migration 090 found an unversioned package product state'
            USING ERRCODE = 'P9002';
    END IF;
END;
$$;

CREATE TABLE package_offer_publication_events (
    id uuid PRIMARY KEY,
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    lifecycle_revision bigint NOT NULL CHECK (lifecycle_revision > 0),
    event_type text NOT NULL CHECK (event_type IN ('publish','replace','withdraw')),
    previous_product_revision bigint CHECK (previous_product_revision > 0),
    write_request_id uuid NOT NULL UNIQUE
        REFERENCES package_catalog_write_requests(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    catalog_sequence bigint NOT NULL UNIQUE CHECK (catalog_sequence > 0),
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (product_id, lifecycle_revision),
    CHECK (
        (event_type='publish' AND previous_product_revision IS NULL) OR
        (event_type IN ('replace','withdraw') AND previous_product_revision IS NOT NULL)
    )
);

CREATE TABLE package_offer_publication_heads (
    product_id uuid PRIMARY KEY REFERENCES package_products(id) ON DELETE RESTRICT,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    lifecycle_revision bigint NOT NULL CHECK (lifecycle_revision > 0),
    state text NOT NULL CHECK (state IN ('published','withdrawn')),
    publication_event_id uuid NOT NULL UNIQUE
        REFERENCES package_offer_publication_events(id) ON DELETE RESTRICT,
    published_at timestamptz NOT NULL CHECK (isfinite(published_at)),
    withdrawn_at timestamptz CHECK (withdrawn_at IS NULL OR isfinite(withdrawn_at)),
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT,
    CHECK ((state='published' AND withdrawn_at IS NULL) OR
           (state='withdrawn' AND withdrawn_at IS NOT NULL))
);

CREATE FUNCTION next_package_catalog_sequence_090()
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    result bigint;
BEGIN
    UPDATE package_catalog_commit_watermark_090
    SET high_water=high_water+1
    WHERE singleton
    RETURNING high_water INTO result;
    IF result IS NULL THEN
        RAISE EXCEPTION 'package catalog commit watermark is unavailable'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN result;
END;
$$;

CREATE FUNCTION capture_package_group_state_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    fact_action text;
    sequence_value bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.deleted_at IS NOT NULL OR
           NEW.created_by_user_id<>NEW.updated_by_user_id THEN
            RAISE EXCEPTION 'invalid initial package group state'
                USING ERRCODE = 'P9002';
        END IF;
        fact_action := 'package.group.create';
    ELSE
        IF NEW.id<>OLD.id OR NEW.revision<>OLD.revision+1 OR OLD.deleted_at IS NOT NULL OR
           NEW.created_by_user_id<>OLD.created_by_user_id OR NEW.created_at<>OLD.created_at THEN
            RAISE EXCEPTION 'invalid package group state transition'
                USING ERRCODE = 'P9002';
        END IF;
        IF NEW.deleted_at IS NOT NULL THEN
            fact_action := 'package.group.delete';
        ELSE
            fact_action := 'package.group.update';
        END IF;
    END IF;
    sequence_value := next_package_catalog_sequence_090();
    INSERT INTO package_group_state_facts_090(
        group_id,revision,name,visible,sort_order,deleted,actor_user_id,action,catalog_sequence
    ) VALUES(NEW.id,NEW.revision,NEW.name,NEW.visible,NEW.sort_order,
             NEW.deleted_at IS NOT NULL,NEW.updated_by_user_id,fact_action,sequence_value);
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_groups_capture_state_090
AFTER INSERT OR UPDATE ON package_groups
FOR EACH ROW EXECUTE FUNCTION capture_package_group_state_090();

CREATE FUNCTION capture_package_product_state_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    fact_action text;
    sequence_value bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.deleted_at IS NOT NULL OR
           NEW.created_by_user_id<>NEW.updated_by_user_id THEN
            RAISE EXCEPTION 'invalid initial package product state'
                USING ERRCODE = 'P9002';
        END IF;
        fact_action := 'package.product.create';
    ELSE
        IF NEW.id<>OLD.id OR NEW.revision<>OLD.revision+1 OR OLD.deleted_at IS NOT NULL OR
           NEW.created_by_user_id<>OLD.created_by_user_id OR NEW.created_at<>OLD.created_at THEN
            RAISE EXCEPTION 'invalid package product state transition'
                USING ERRCODE = 'P9002';
        END IF;
        IF NEW.deleted_at IS NOT NULL THEN
            fact_action := 'package.product.delete';
        ELSE
            fact_action := 'package.product.update';
        END IF;
    END IF;
    sequence_value := next_package_catalog_sequence_090();
    INSERT INTO package_product_state_facts_090(
        product_id,revision,name,enabled,sort_order,spec,deleted,
        actor_user_id,action,catalog_sequence
    ) VALUES(NEW.id,NEW.revision,NEW.name,NEW.enabled,NEW.sort_order,NEW.spec,
             NEW.deleted_at IS NOT NULL,NEW.updated_by_user_id,fact_action,sequence_value);
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_products_capture_state_090
AFTER INSERT OR UPDATE ON package_products
FOR EACH ROW EXECUTE FUNCTION capture_package_product_state_090();

CREATE FUNCTION bind_package_catalog_audit_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parsed_resource uuid;
    parsed_revision bigint;
    sequence_value bigint;
    kind_value text;
    scope_kind text;
    scope_tenant uuid;
BEGIN
    IF NEW.result<>'success' OR NEW.action NOT IN (
        'package.group.create','package.group.update','package.group.delete',
        'package.product.create','package.product.update','package.product.delete',
        'package.product.publish','package.product.withdraw'
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.actor_user_id IS NULL OR
       NEW.resource_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'invalid package catalog audit identity'
            USING ERRCODE = 'P9002';
    END IF;
    parsed_resource := NEW.resource_id::uuid;
    SELECT kind,tenant_id INTO scope_kind,scope_tenant
    FROM access_scopes WHERE id=NEW.scope_id FOR SHARE;
    IF scope_kind IS DISTINCT FROM 'platform' OR scope_tenant IS NOT NULL THEN
        RAISE EXCEPTION 'package catalog audit scope is not platform'
            USING ERRCODE = 'P9002';
    END IF;

    IF NEW.action LIKE 'package.group.%' THEN
        IF NEW.resource_type<>'package_group' OR
           NEW.payload->>'revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package group audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'revision')::bigint;
        SELECT fact.catalog_sequence INTO sequence_value
        FROM package_group_state_facts_090 fact
        WHERE fact.group_id=parsed_resource AND fact.revision=parsed_revision
          AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
          AND ((NEW.action='package.group.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision)) OR
               (NEW.action<>'package.group.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision,'visible',fact.visible)));
        kind_value := 'group';
    ELSIF NEW.action IN ('package.product.create','package.product.update','package.product.delete') THEN
        IF NEW.resource_type<>'package_product' OR
           NEW.payload->>'revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package product audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'revision')::bigint;
        SELECT fact.catalog_sequence INTO sequence_value
        FROM package_product_state_facts_090 fact
        WHERE fact.product_id=parsed_resource AND fact.revision=parsed_revision
          AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
          AND ((NEW.action='package.product.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision)) OR
               (NEW.action<>'package.product.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision,'enabled',fact.enabled)));
        kind_value := 'product';
    ELSE
        IF NEW.resource_type<>'package_product' OR
           NEW.payload->>'product_revision' !~ '^[1-9][0-9]{0,18}$' OR
           NEW.payload->>'lifecycle_revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package publication audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'lifecycle_revision')::bigint;
        SELECT event.catalog_sequence INTO sequence_value
        FROM package_offer_publication_events event
        WHERE event.product_id=parsed_resource
          AND event.product_revision=(NEW.payload->>'product_revision')::bigint
          AND event.lifecycle_revision=parsed_revision
          AND event.actor_scope_id=NEW.scope_id AND event.actor_user_id=NEW.actor_user_id
          AND event.occurred_at=NEW.occurred_at
          AND NEW.action=CASE WHEN event.event_type='withdraw'
              THEN 'package.product.withdraw' ELSE 'package.product.publish' END
          AND ((event.event_type='withdraw' AND NEW.payload=jsonb_build_object(
                'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision)) OR
               (event.event_type<>'withdraw' AND NEW.payload=jsonb_build_object(
                'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision,
                'event_type',event.event_type)));
        kind_value := 'publication';
    END IF;
    IF sequence_value IS NULL OR sequence_value=0 OR EXISTS (
        SELECT 1 FROM package_catalog_audit_links_090
        WHERE catalog_sequence=sequence_value OR audit_event_id=NEW.id
    ) THEN
        RAISE EXCEPTION 'package catalog audit has no unique source fact'
            USING ERRCODE = 'P9002';
    END IF;
    INSERT INTO package_catalog_audit_links_090(
        catalog_sequence,audit_event_id,fact_kind,scope_id,actor_user_id,
        action,resource_id,resource_revision
    ) VALUES(sequence_value,NEW.id,kind_value,NEW.scope_id,NEW.actor_user_id,
             NEW.action,parsed_resource,parsed_revision);
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_events_bind_package_catalog_090
AFTER INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION bind_package_catalog_audit_090();

CREATE FUNCTION require_package_catalog_sequence_completion_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM package_catalog_audit_links_090 link
        WHERE link.catalog_sequence=NEW.high_water
          AND (
            (link.fact_kind='group' AND EXISTS (
                SELECT 1 FROM package_group_state_facts_090 fact
                WHERE fact.catalog_sequence=NEW.high_water
                  AND fact.group_id=link.resource_id
                  AND fact.revision=link.resource_revision
            )) OR
            (link.fact_kind='product' AND EXISTS (
                SELECT 1 FROM package_product_state_facts_090 fact
                WHERE fact.catalog_sequence=NEW.high_water
                  AND fact.product_id=link.resource_id
                  AND fact.revision=link.resource_revision
            )) OR
            (link.fact_kind='publication' AND EXISTS (
                SELECT 1 FROM package_offer_publication_events event
                WHERE event.catalog_sequence=NEW.high_water
                  AND event.product_id=link.resource_id
                  AND event.lifecycle_revision=link.resource_revision
            ))
          )
    ) THEN
        RAISE EXCEPTION 'package catalog sequence did not complete atomically'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_catalog_watermark_completed_090
AFTER UPDATE ON package_catalog_commit_watermark_090
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_package_catalog_sequence_completion_090();

CREATE FUNCTION require_package_group_state_audit_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.catalog_sequence=0 THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM package_catalog_audit_links_090 link
        JOIN package_groups source ON source.id=NEW.group_id
        WHERE link.catalog_sequence=NEW.catalog_sequence AND link.fact_kind='group'
          AND link.actor_user_id=NEW.actor_user_id AND link.action=NEW.action
          AND link.resource_id=NEW.group_id AND link.resource_revision=NEW.revision
          AND source.revision=NEW.revision AND source.name=NEW.name
          AND source.visible=NEW.visible AND source.sort_order=NEW.sort_order
          AND (source.deleted_at IS NOT NULL)=NEW.deleted
          AND source.updated_by_user_id=NEW.actor_user_id
    ) THEN
        RAISE EXCEPTION 'package group state fact did not complete atomically'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_group_state_facts_audited_090
AFTER INSERT ON package_group_state_facts_090
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_package_group_state_audit_090();

CREATE FUNCTION require_package_product_state_audit_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.catalog_sequence=0 THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM package_catalog_audit_links_090 link
        JOIN package_products source ON source.id=NEW.product_id
        JOIN package_product_versions version
          ON version.product_id=NEW.product_id AND version.revision=NEW.revision
        WHERE link.catalog_sequence=NEW.catalog_sequence AND link.fact_kind='product'
          AND link.actor_user_id=NEW.actor_user_id AND link.action=NEW.action
          AND link.resource_id=NEW.product_id AND link.resource_revision=NEW.revision
          AND source.revision=NEW.revision AND source.name=NEW.name
          AND source.enabled=NEW.enabled AND source.sort_order=NEW.sort_order
          AND source.spec=NEW.spec AND (source.deleted_at IS NOT NULL)=NEW.deleted
          AND source.updated_by_user_id=NEW.actor_user_id
          AND version.name=NEW.name AND version.enabled=NEW.enabled
          AND version.sort_order=NEW.sort_order AND version.spec=NEW.spec
          AND version.deleted=NEW.deleted
    ) THEN
        RAISE EXCEPTION 'package product state fact did not complete atomically'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_product_state_facts_audited_090
AFTER INSERT ON package_product_state_facts_090
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_package_product_state_audit_090();

CREATE FUNCTION package_offer_spec_publishable_090(product_spec jsonb, checked_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql
STABLE
STRICT
AS $$
DECLARE
	group_value jsonb;
	group_text text;
	limit_key text;
	limit_text text;
	price_key text;
	price_text text;
    site_limit_text text;
    node_limit_text text;
    per_user_limit_text text;
    custom_days_text text;
    numerator_text text;
    denominator_text text;
	region_text text;
	node_group_text text;
	backup_node_group_text text;
	sort_order_text text;
	factor_left numeric;
	factor_right numeric;
	factor_remainder numeric;
    cycle_kind_text text;
    timezone_text text;
    sale_expires_text text;
BEGIN
    IF jsonb_typeof(product_spec) IS DISTINCT FROM 'object' OR
	   product_spec - ARRAY['name','description','group_ids','region_id','node_group_id',
		'backup_node_group_id','limits','protection','prices','cname','purchase','commercial_terms',
		'sort_order','enabled'] <> '{}'::jsonb OR
	   NOT (product_spec ?& ARRAY['name','description','group_ids','region_id','node_group_id',
		'backup_node_group_id','limits','protection','prices','cname','purchase','commercial_terms',
		'sort_order','enabled']) OR
	   jsonb_typeof(product_spec#>'{name}') IS DISTINCT FROM 'string' OR
	   btrim(product_spec#>>'{name}') IS DISTINCT FROM product_spec#>>'{name}' OR
	   char_length(product_spec#>>'{name}') NOT BETWEEN 1 AND 128 OR
	   jsonb_typeof(product_spec#>'{description}') IS DISTINCT FROM 'string' OR
	   btrim(product_spec#>>'{description}') IS DISTINCT FROM product_spec#>>'{description}' OR
	   char_length(product_spec#>>'{description}') > 1000 OR
	   jsonb_typeof(product_spec#>'{group_ids}') IS DISTINCT FROM 'array' OR
	   jsonb_array_length(product_spec#>'{group_ids}') NOT BETWEEN 1 AND 32 OR
	   jsonb_typeof(product_spec#>'{limits}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{limits}') - ARRAY['monthly_traffic_bytes','bandwidth_bps','connections',
		'stream_ports','domains','root_domains','http_ports','custom_cc','websocket','http3','l2_origin'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{limits}' ?& ARRAY['monthly_traffic_bytes','bandwidth_bps','connections',
		'stream_ports','domains','root_domains','http_ports','custom_cc','websocket','http3','l2_origin']) OR
	   jsonb_typeof(product_spec#>'{protection}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{protection}') - ARRAY['cc','ddos'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{protection}' ?& ARRAY['cc','ddos']) OR
	   jsonb_typeof(product_spec#>'{prices}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{prices}') - ARRAY['currency','monthly_minor','quarterly_minor','yearly_minor'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{prices}' ?& ARRAY['currency','monthly_minor','quarterly_minor','yearly_minor']) OR
	   jsonb_typeof(product_spec#>'{cname}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{cname}') - ARRAY['hostname','domain','mode'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{cname}' ?& ARRAY['hostname','domain','mode']) OR
	   jsonb_typeof(product_spec#>'{purchase}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{purchase}') - ARRAY['per_user_limit','sale_expires_at','require_real_name',
		'renew_before_days','restrict_source_ips'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{purchase}' ?& ARRAY['per_user_limit','sale_expires_at','require_real_name',
		'renew_before_days','restrict_source_ips']) OR
	   jsonb_typeof(product_spec#>'{commercial_terms}') IS DISTINCT FROM 'object' OR
	   (product_spec#>'{commercial_terms}') - ARRAY['site_limit','node_limit','timezone','cycle_kind',
		'custom_cycle_days','tcp_factor_numerator','tcp_factor_denominator'] <> '{}'::jsonb OR
	   NOT (product_spec#>'{commercial_terms}' ?& ARRAY['site_limit','node_limit','timezone','cycle_kind',
		'custom_cycle_days','tcp_factor_numerator','tcp_factor_denominator']) OR
	   jsonb_typeof(product_spec#>'{limits,custom_cc}') IS DISTINCT FROM 'boolean' OR
	   jsonb_typeof(product_spec#>'{limits,websocket}') IS DISTINCT FROM 'boolean' OR
	   jsonb_typeof(product_spec#>'{limits,http3}') IS DISTINCT FROM 'boolean' OR
	   jsonb_typeof(product_spec#>'{limits,l2_origin}') IS DISTINCT FROM 'boolean' OR
	   jsonb_typeof(product_spec#>'{prices,currency}') IS DISTINCT FROM 'string' OR
	   product_spec#>>'{prices,currency}' IS DISTINCT FROM 'CNY' OR
	   jsonb_typeof(product_spec#>'{purchase,restrict_source_ips}') IS DISTINCT FROM 'boolean' OR
       product_spec#>'{purchase,restrict_source_ips}' IS DISTINCT FROM 'false'::jsonb OR
       jsonb_typeof(product_spec#>'{purchase,renew_before_days}') IS DISTINCT FROM 'number' OR
       product_spec#>>'{purchase,renew_before_days}' IS DISTINCT FROM '-1' OR
	   jsonb_typeof(product_spec#>'{purchase,require_real_name}') IS DISTINCT FROM 'boolean' OR
	   jsonb_typeof(product_spec#>'{purchase,per_user_limit}') IS DISTINCT FROM 'number' OR
	   NOT (product_spec#>'{purchase}' ? 'sale_expires_at') OR
	   jsonb_typeof(product_spec#>'{commercial_terms,site_limit}') IS DISTINCT FROM 'number' OR
       jsonb_typeof(product_spec#>'{commercial_terms,node_limit}') IS DISTINCT FROM 'number' OR
       jsonb_typeof(product_spec#>'{commercial_terms,timezone}') IS DISTINCT FROM 'string' OR
       jsonb_typeof(product_spec#>'{commercial_terms,cycle_kind}') IS DISTINCT FROM 'string' OR
       jsonb_typeof(product_spec#>'{commercial_terms,custom_cycle_days}') IS DISTINCT FROM 'number' OR
	   jsonb_typeof(product_spec#>'{commercial_terms,tcp_factor_numerator}') IS DISTINCT FROM 'number' OR
	   jsonb_typeof(product_spec#>'{commercial_terms,tcp_factor_denominator}') IS DISTINCT FROM 'number' OR
	   jsonb_typeof(product_spec#>'{sort_order}') IS DISTINCT FROM 'number' OR
	   jsonb_typeof(product_spec#>'{enabled}') IS DISTINCT FROM 'boolean' THEN
        RETURN false;
    END IF;

	region_text := product_spec#>>'{region_id}';
	node_group_text := product_spec#>>'{node_group_id}';
	backup_node_group_text := product_spec#>>'{backup_node_group_id}';
	sort_order_text := product_spec#>>'{sort_order}';
	IF jsonb_typeof(product_spec#>'{region_id}') IS DISTINCT FROM 'string' OR
	   jsonb_typeof(product_spec#>'{node_group_id}') IS DISTINCT FROM 'string' OR
	   region_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
	   node_group_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
	   region_text='00000000-0000-0000-0000-000000000000' OR
	   node_group_text='00000000-0000-0000-0000-000000000000' OR
	   (product_spec#>'{backup_node_group_id}' <> 'null'::jsonb AND (
		jsonb_typeof(product_spec#>'{backup_node_group_id}') IS DISTINCT FROM 'string' OR
		backup_node_group_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
		backup_node_group_text='00000000-0000-0000-0000-000000000000' OR
		backup_node_group_text=node_group_text
	   )) OR sort_order_text !~ '^[0-9]+$' OR sort_order_text::numeric > 1000000 THEN
		RETURN false;
	END IF;

	IF jsonb_typeof(product_spec#>'{protection,cc}') IS DISTINCT FROM 'string' OR
	   jsonb_typeof(product_spec#>'{protection,ddos}') IS DISTINCT FROM 'string' OR
	   btrim(product_spec#>>'{protection,cc}') IS DISTINCT FROM product_spec#>>'{protection,cc}' OR
	   btrim(product_spec#>>'{protection,ddos}') IS DISTINCT FROM product_spec#>>'{protection,ddos}' OR
	   char_length(product_spec#>>'{protection,cc}') > 256 OR
	   char_length(product_spec#>>'{protection,ddos}') > 256 OR
	   jsonb_typeof(product_spec#>'{cname,hostname}') IS DISTINCT FROM 'string' OR
	   jsonb_typeof(product_spec#>'{cname,domain}') IS DISTINCT FROM 'string' OR
	   jsonb_typeof(product_spec#>'{cname,mode}') IS DISTINCT FROM 'string' OR
	   product_spec#>>'{cname,mode}' NOT IN ('per_site','shared') OR
	   char_length(product_spec#>>'{cname,domain}') NOT BETWEEN 1 AND 253 OR
	   product_spec#>>'{cname,domain}' !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' OR
	   (product_spec#>>'{cname,hostname}' <> '' AND (
		char_length(product_spec#>>'{cname,hostname}') > 253 OR
		product_spec#>>'{cname,hostname}' !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
	   )) THEN
		RETURN false;
	END IF;

	FOR group_value IN SELECT value FROM jsonb_array_elements(product_spec#>'{group_ids}') LOOP
		IF jsonb_typeof(group_value) IS DISTINCT FROM 'string' THEN
			RETURN false;
		END IF;
		group_text := group_value#>>'{}';
		IF group_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
		   group_text='00000000-0000-0000-0000-000000000000' THEN
			RETURN false;
		END IF;
	END LOOP;
	IF (SELECT count(DISTINCT value#>>'{}') FROM jsonb_array_elements(product_spec#>'{group_ids}')) <>
	   jsonb_array_length(product_spec#>'{group_ids}') THEN
		RETURN false;
	END IF;

	FOREACH limit_key IN ARRAY ARRAY[
		'monthly_traffic_bytes','bandwidth_bps','connections','stream_ports',
		'domains','root_domains','http_ports'
	] LOOP
		IF jsonb_typeof(product_spec#>ARRAY['limits',limit_key]) IS DISTINCT FROM 'number' THEN
			RETURN false;
		END IF;
		limit_text := product_spec#>>ARRAY['limits',limit_key];
		IF limit_text !~ '^(-1|[0-9]+)$' OR
		   (limit_key='monthly_traffic_bytes' AND limit_text::numeric > 1152921504606846976) OR
		   (limit_key='bandwidth_bps' AND limit_text::numeric > 1000000000000000) OR
		   (limit_key NOT IN ('monthly_traffic_bytes','bandwidth_bps') AND
			limit_text::numeric > 1000000000) THEN
			RETURN false;
		END IF;
	END LOOP;

	FOREACH price_key IN ARRAY ARRAY['monthly_minor','quarterly_minor','yearly_minor'] LOOP
		IF jsonb_typeof(product_spec#>ARRAY['prices',price_key]) IS DISTINCT FROM 'number' THEN
			RETURN false;
		END IF;
		price_text := product_spec#>>ARRAY['prices',price_key];
		IF price_text !~ '^[0-9]+$' OR price_text::numeric > 1000000000000000 THEN
			RETURN false;
		END IF;
	END LOOP;

    site_limit_text := product_spec#>>'{commercial_terms,site_limit}';
    node_limit_text := product_spec#>>'{commercial_terms,node_limit}';
    per_user_limit_text := product_spec#>>'{purchase,per_user_limit}';
    custom_days_text := product_spec#>>'{commercial_terms,custom_cycle_days}';
    numerator_text := product_spec#>>'{commercial_terms,tcp_factor_numerator}';
    denominator_text := product_spec#>>'{commercial_terms,tcp_factor_denominator}';
    cycle_kind_text := product_spec#>>'{commercial_terms,cycle_kind}';
    timezone_text := product_spec#>>'{commercial_terms,timezone}';

    IF site_limit_text !~ '^(-1|[0-9]+)$' OR node_limit_text !~ '^(-1|[0-9]+)$' OR
       per_user_limit_text !~ '^(-1|[0-9]+)$' OR custom_days_text !~ '^[0-9]+$' OR
       numerator_text !~ '^[1-9][0-9]*$' OR denominator_text !~ '^[1-9][0-9]*$' OR
       site_limit_text::numeric > 1000000000 OR node_limit_text::numeric > 1000000000 OR
       per_user_limit_text::numeric > 1000000000 OR custom_days_text::numeric > 366 OR
	   cycle_kind_text NOT IN ('daily','monthly','custom_days') OR
       (cycle_kind_text IN ('daily','monthly') AND custom_days_text <> '0') OR
       (cycle_kind_text='custom_days' AND custom_days_text::numeric < 1) OR
       NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name=timezone_text) THEN
        RETURN false;
    END IF;
	factor_left := numerator_text::numeric;
	factor_right := denominator_text::numeric;
	WHILE factor_right <> 0 LOOP
		factor_remainder := mod(factor_left,factor_right);
		factor_left := factor_right;
		factor_right := factor_remainder;
	END LOOP;
	IF numerator_text::numeric/factor_left > 1000000 OR
	   denominator_text::numeric/factor_left > 1000000 OR
	   numerator_text::numeric/factor_left > denominator_text::numeric/factor_left*1000 THEN
		RETURN false;
	END IF;

    IF product_spec#>'{purchase,sale_expires_at}' IS NOT NULL AND
       product_spec#>'{purchase,sale_expires_at}' <> 'null'::jsonb THEN
        IF jsonb_typeof(product_spec#>'{purchase,sale_expires_at}') IS DISTINCT FROM 'string' THEN
            RETURN false;
        END IF;
        sale_expires_text := product_spec#>>'{purchase,sale_expires_at}';
		IF sale_expires_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,5}[1-9])?Z$' OR
		   NOT isfinite(sale_expires_text::timestamptz) OR
		   sale_expires_text::timestamptz <= checked_at THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
EXCEPTION WHEN others THEN
    RETURN false;
END;
$$;

CREATE FUNCTION validate_package_offer_publication_event_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_head package_offer_publication_heads%ROWTYPE;
	head_found boolean;
    product_spec jsonb;
    product_deleted boolean;
    product_enabled boolean;
    version_enabled boolean;
    product_matches_version boolean;
    product_current_revision bigint;
    claimed_operation text;
    claimed_scope uuid;
    claimed_actor uuid;
    claimed_complete timestamptz;
	actor_scope_kind text;
	actor_scope_tenant uuid;
	actor_membership_status text;
	actor_user_status text;
	actor_can_manage boolean;
BEGIN
	IF NEW.catalog_sequence IS NOT NULL THEN
		RAISE EXCEPTION 'package offer catalog sequence is server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	PERFORM iam_global_lock_shared_v1();
	PERFORM iam_scope_locks_v1(ARRAY[NEW.actor_scope_id]);
	SELECT scope.kind,scope.tenant_id,membership.status,account.status
	INTO actor_scope_kind,actor_scope_tenant,actor_membership_status,actor_user_status
	FROM access_scopes scope
	JOIN memberships membership
	  ON membership.scope_id=scope.id AND membership.user_id=NEW.actor_user_id
	JOIN users account ON account.id=membership.user_id
	WHERE scope.id=NEW.actor_scope_id
	FOR SHARE OF scope,membership,account;
	PERFORM 1
	FROM role_assignments assignment
	JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
	WHERE assignment.scope_id=NEW.actor_scope_id AND assignment.user_id=NEW.actor_user_id
	ORDER BY assignment.role_id
	FOR SHARE OF assignment,role;
	PERFORM 1 FROM permissions permission
	WHERE permission.name='packages.manage'
	FOR SHARE OF permission;
	PERFORM 1
	FROM role_assignments assignment
	JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
	JOIN role_permissions grant_row ON grant_row.role_id=role.id
	WHERE assignment.scope_id=NEW.actor_scope_id AND assignment.user_id=NEW.actor_user_id
	ORDER BY grant_row.role_id,grant_row.permission_name
	FOR SHARE OF assignment,role,grant_row;
	SELECT EXISTS (
		SELECT 1 FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=NEW.actor_scope_id
		  AND assignment.user_id=NEW.actor_user_id
		  AND grant_row.permission_name='packages.manage'
	) INTO actor_can_manage;
	IF actor_scope_kind IS DISTINCT FROM 'platform' OR actor_scope_tenant IS NOT NULL OR
	   actor_membership_status IS DISTINCT FROM 'active' OR
	   actor_user_status IS DISTINCT FROM 'active' OR actor_can_manage IS DISTINCT FROM true THEN
		RAISE EXCEPTION 'package offer publication actor is unauthorized'
			USING ERRCODE = 'P9002';
	END IF;

    PERFORM 1 FROM package_offer_lifecycle_lock WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'package offer lifecycle lock is unavailable'
            USING ERRCODE = 'P9002';
    END IF;

    SELECT operation,actor_scope_id,actor_user_id,completed_at
    INTO claimed_operation,claimed_scope,claimed_actor,claimed_complete
    FROM package_catalog_write_requests
    WHERE id=NEW.write_request_id
    FOR UPDATE;
    IF NOT FOUND OR claimed_complete IS NOT NULL OR claimed_scope<>NEW.actor_scope_id OR
       claimed_actor<>NEW.actor_user_id OR
       claimed_operation<>(CASE NEW.event_type
           WHEN 'withdraw' THEN 'package.product.withdraw'
           ELSE 'package.product.publish'
       END) THEN
        RAISE EXCEPTION 'invalid package offer publication write claim'
            USING ERRCODE = 'P9002';
    END IF;

	SELECT * INTO current_head
	FROM package_offer_publication_heads
	WHERE product_id=NEW.product_id
	FOR UPDATE;
	head_found := FOUND;

	IF NEW.event_type='withdraw' THEN
		IF NOT head_found OR current_head.state<>'published' OR
		   NEW.lifecycle_revision<>current_head.lifecycle_revision+1 OR
		   NEW.previous_product_revision<>current_head.product_revision OR
		   NEW.product_revision<>current_head.product_revision THEN
			RAISE EXCEPTION 'invalid package offer withdrawal'
				USING ERRCODE = 'P9002';
		END IF;
		NEW.catalog_sequence := next_package_catalog_sequence_090();
		RETURN NEW;
	END IF;

    SELECT version.spec,product.deleted_at IS NOT NULL,product.enabled,version.enabled,
           product.spec=version.spec AND product.name=version.name AND
		   product.sort_order=version.sort_order AND
		   version.spec#>>'{name}'=version.name AND
		   version.spec#>>'{sort_order}'=version.sort_order::text AND
		   version.spec#>'{enabled}'=to_jsonb(version.enabled),product.revision
    INTO product_spec,product_deleted,product_enabled,version_enabled,
         product_matches_version,product_current_revision
    FROM package_product_versions version
    JOIN package_products product ON product.id=version.product_id
    WHERE version.product_id=NEW.product_id AND version.revision=NEW.product_revision
      AND NOT version.deleted
    FOR SHARE OF product;
    IF NOT FOUND OR product_deleted OR NOT product_enabled OR NOT version_enabled OR
	   product_matches_version IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'package offer revision is unavailable'
            USING ERRCODE = 'P9002';
    END IF;

    IF NEW.event_type='publish' THEN
		IF head_found OR NEW.lifecycle_revision<>1 OR NEW.previous_product_revision IS NOT NULL OR
           product_current_revision<>NEW.product_revision THEN
            RAISE EXCEPTION 'invalid initial package offer publication'
                USING ERRCODE = 'P9002';
        END IF;
    ELSIF NEW.event_type='replace' THEN
		IF NOT head_found OR current_head.state<>'published' OR
           NEW.lifecycle_revision<>current_head.lifecycle_revision+1 OR
           NEW.previous_product_revision<>current_head.product_revision OR
           NEW.product_revision<=current_head.product_revision OR
           product_current_revision<>NEW.product_revision THEN
            RAISE EXCEPTION 'invalid package offer replacement'
                USING ERRCODE = 'P9002';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package offer publication event'
            USING ERRCODE = 'P9002';
    END IF;

    IF NOT package_offer_spec_publishable_090(product_spec, clock_timestamp()) THEN
        RAISE EXCEPTION 'package offer publication policy is unsupported or expired'
            USING ERRCODE = 'P9002';
    END IF;
	NEW.catalog_sequence := next_package_catalog_sequence_090();
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_offer_publication_events_validate_090
BEFORE INSERT ON package_offer_publication_events
FOR EACH ROW EXECUTE FUNCTION validate_package_offer_publication_event_090();

CREATE FUNCTION project_package_offer_publication_head_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_type='withdraw' THEN
        UPDATE package_offer_publication_heads
        SET lifecycle_revision=NEW.lifecycle_revision,state='withdrawn',
            publication_event_id=NEW.id,withdrawn_at=NEW.occurred_at
        WHERE product_id=NEW.product_id AND product_revision=NEW.product_revision;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'package offer withdrawal lost its current head'
                USING ERRCODE = 'P9002';
        END IF;
    ELSIF NEW.event_type='replace' THEN
        UPDATE package_offer_publication_heads
        SET product_revision=NEW.product_revision,
            lifecycle_revision=NEW.lifecycle_revision,
            state='published',publication_event_id=NEW.id,
            published_at=NEW.occurred_at,withdrawn_at=NULL
        WHERE product_id=NEW.product_id
          AND product_revision=NEW.previous_product_revision
          AND lifecycle_revision=NEW.lifecycle_revision-1
          AND state='published';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'package offer replacement lost its current head'
                USING ERRCODE = 'P9002';
        END IF;
    ELSE
        INSERT INTO package_offer_publication_heads(
            product_id,product_revision,lifecycle_revision,state,
            publication_event_id,published_at,withdrawn_at
        ) VALUES(NEW.product_id,NEW.product_revision,NEW.lifecycle_revision,'published',
                 NEW.id,NEW.occurred_at,NULL);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER package_offer_publication_events_project_head_090
AFTER INSERT ON package_offer_publication_events
FOR EACH ROW EXECUTE FUNCTION project_package_offer_publication_head_090();

CREATE FUNCTION require_package_offer_publication_completion_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM package_catalog_write_requests request
		JOIN audit_events audit
		  ON audit.scope_id=NEW.actor_scope_id
		 AND audit.actor_user_id=NEW.actor_user_id
		 AND audit.action=CASE WHEN NEW.event_type='withdraw'
			THEN 'package.product.withdraw' ELSE 'package.product.publish' END
		 AND audit.resource_type='package_product'
		 AND audit.resource_id=NEW.product_id::text
		 AND audit.result='success'
		 AND audit.occurred_at=NEW.occurred_at
		 AND audit.payload->>'product_revision'=NEW.product_revision::text
		 AND audit.payload->>'lifecycle_revision'=NEW.lifecycle_revision::text
		 AND (NEW.event_type='withdraw' OR audit.payload->>'event_type'=NEW.event_type)
		JOIN package_catalog_audit_links_090 link
		  ON link.catalog_sequence=NEW.catalog_sequence
		 AND link.audit_event_id=audit.id
		 AND link.fact_kind='publication'
        WHERE request.id=NEW.write_request_id
          AND request.actor_scope_id=NEW.actor_scope_id
          AND request.actor_user_id=NEW.actor_user_id
          AND request.resource_id=NEW.product_id
          AND request.response_status=200
          AND request.response_body IS NOT NULL
          AND request.completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'package offer publication write did not complete atomically'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_offer_publication_events_completed_090
AFTER INSERT ON package_offer_publication_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_package_offer_publication_completion_090();

CREATE FUNCTION protect_package_offer_catalog_request_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_OP='TRUNCATE' THEN
		IF EXISTS (SELECT 1 FROM package_offer_publication_events) THEN
			RAISE EXCEPTION 'package offer publication request provenance is immutable'
				USING ERRCODE = 'P9002';
		END IF;
		RETURN NULL;
	END IF;
	IF EXISTS (
		SELECT 1 FROM package_offer_publication_events event
		WHERE event.write_request_id=OLD.id
	) THEN
		IF TG_OP='UPDATE' AND OLD.resource_id IS NULL AND OLD.response_status IS NULL AND
		   OLD.response_body IS NULL AND OLD.completed_at IS NULL AND
		   NEW.id=OLD.id AND NEW.actor_user_id=OLD.actor_user_id AND
		   NEW.actor_scope_id=OLD.actor_scope_id AND NEW.operation=OLD.operation AND
		   NEW.idempotency_key=OLD.idempotency_key AND NEW.request_digest=OLD.request_digest AND
		   NEW.created_at=OLD.created_at AND NEW.resource_id IS NOT NULL AND
		   NEW.response_status=200 AND NEW.response_body IS NOT NULL AND
		   NEW.completed_at IS NOT NULL THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package offer publication request provenance is immutable'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_OP='DELETE' THEN
		RETURN OLD;
	END IF;
	RETURN NEW;
END;
$$;

CREATE TRIGGER package_offer_catalog_requests_provenance_immutable_090
BEFORE UPDATE OR DELETE ON package_catalog_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_package_offer_catalog_request_090();
CREATE TRIGGER package_offer_catalog_requests_no_truncate_090
BEFORE TRUNCATE ON package_catalog_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_offer_catalog_request_090();

CREATE FUNCTION protect_package_offer_publication_head_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    publication_event package_offer_publication_events%ROWTYPE;
BEGIN
    SELECT * INTO publication_event
    FROM package_offer_publication_events event
	WHERE event.id=NEW.publication_event_id;
    IF NOT FOUND OR publication_event.product_id<>NEW.product_id OR
       publication_event.product_revision<>NEW.product_revision OR
       publication_event.lifecycle_revision<>NEW.lifecycle_revision OR
	   (TG_OP='INSERT' AND (
		publication_event.event_type<>'publish' OR NEW.lifecycle_revision<>1 OR
		publication_event.previous_product_revision IS NOT NULL
	   )) OR
	   (TG_OP='UPDATE' AND (
		NEW.product_id<>OLD.product_id OR
		publication_event.lifecycle_revision<>OLD.lifecycle_revision+1 OR
		publication_event.previous_product_revision<>OLD.product_revision
	   )) OR
       (publication_event.event_type='withdraw' AND (
		   TG_OP<>'UPDATE' OR NEW.state<>'withdrawn' OR
		   NEW.product_revision<>OLD.product_revision OR
           NEW.withdrawn_at IS DISTINCT FROM publication_event.occurred_at OR
		   NEW.published_at IS DISTINCT FROM OLD.published_at
       )) OR
	   (publication_event.event_type='replace' AND (
		   TG_OP<>'UPDATE' OR NEW.product_revision<=OLD.product_revision OR
		   NEW.state<>'published' OR NEW.published_at IS DISTINCT FROM publication_event.occurred_at OR
		   NEW.withdrawn_at IS NOT NULL
	   )) OR
	   (publication_event.event_type='publish' AND (
		   TG_OP<>'INSERT' OR
           NEW.state<>'published' OR NEW.published_at IS DISTINCT FROM publication_event.occurred_at OR
           NEW.withdrawn_at IS NOT NULL
       )) THEN
        RAISE EXCEPTION 'package offer publication head is event projected'
            USING ERRCODE = 'P9002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_offer_publication_heads_projected_090
BEFORE INSERT OR UPDATE ON package_offer_publication_heads
FOR EACH ROW EXECUTE FUNCTION protect_package_offer_publication_head_090();

CREATE FUNCTION protect_package_offer_publication_fact_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'package offer publication facts are immutable'
        USING ERRCODE = 'P9002';
END;
$$;

CREATE TRIGGER package_offer_publication_events_append_only
BEFORE UPDATE OR DELETE ON package_offer_publication_events
FOR EACH ROW EXECUTE FUNCTION protect_package_offer_publication_fact_090();
CREATE TRIGGER package_offer_publication_events_no_truncate
BEFORE TRUNCATE ON package_offer_publication_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_offer_publication_fact_090();
CREATE TRIGGER package_offer_publication_heads_no_delete
BEFORE DELETE ON package_offer_publication_heads
FOR EACH ROW EXECUTE FUNCTION protect_package_offer_publication_fact_090();
CREATE TRIGGER package_offer_publication_heads_no_truncate
BEFORE TRUNCATE ON package_offer_publication_heads
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_offer_publication_fact_090();
CREATE TRIGGER package_offer_lifecycle_lock_immutable
BEFORE UPDATE OR DELETE ON package_offer_lifecycle_lock
FOR EACH ROW EXECUTE FUNCTION protect_package_offer_publication_fact_090();
CREATE TRIGGER package_offer_lifecycle_lock_no_truncate
BEFORE TRUNCATE ON package_offer_lifecycle_lock
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_offer_publication_fact_090();

CREATE FUNCTION protect_package_catalog_state_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_TABLE_NAME='package_catalog_commit_watermark_090' THEN
		IF TG_OP='UPDATE' AND
		   NEW.singleton=OLD.singleton AND NEW.high_water=OLD.high_water+1 THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog watermark is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_group_state_facts_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND
		   NEW.catalog_sequence=(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton) AND
		   EXISTS (
			SELECT 1 FROM package_groups source
			WHERE source.id=NEW.group_id AND source.revision=NEW.revision
			  AND source.name=NEW.name AND source.visible=NEW.visible
			  AND source.sort_order=NEW.sort_order
			  AND (source.deleted_at IS NOT NULL)=NEW.deleted
			  AND source.updated_by_user_id=NEW.actor_user_id
			  AND source.xmin=current_package_catalog_xid_090()
			  AND NEW.action=CASE
				WHEN source.revision=1 AND source.deleted_at IS NULL THEN 'package.group.create'
				WHEN source.deleted_at IS NOT NULL THEN 'package.group.delete'
				ELSE 'package.group.update'
			  END
		   ) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog fact is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_product_state_facts_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND
		   NEW.catalog_sequence=(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton) AND
		   EXISTS (
			SELECT 1 FROM package_products source
			WHERE source.id=NEW.product_id AND source.revision=NEW.revision
			  AND source.name=NEW.name AND source.enabled=NEW.enabled
			  AND source.sort_order=NEW.sort_order AND source.spec=NEW.spec
			  AND (source.deleted_at IS NOT NULL)=NEW.deleted
			  AND source.updated_by_user_id=NEW.actor_user_id
			  AND source.xmin=current_package_catalog_xid_090()
			  AND NEW.action=CASE
				WHEN source.revision=1 AND source.deleted_at IS NULL THEN 'package.product.create'
				WHEN source.deleted_at IS NOT NULL THEN 'package.product.delete'
				ELSE 'package.product.update'
			  END
		   ) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog fact is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_catalog_audit_links_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='group' AND EXISTS (
			SELECT 1 FROM package_group_state_facts_090 fact
			JOIN package_groups source ON source.id=fact.group_id AND source.revision=fact.revision
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE fact.catalog_sequence=NEW.catalog_sequence
			  AND fact.group_id=NEW.resource_id AND fact.revision=NEW.resource_revision
			  AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
			  AND fact.xmin=current_package_catalog_xid_090()
			  AND source.xmin=current_package_catalog_xid_090()
			  AND source.name=fact.name AND source.visible=fact.visible
			  AND source.sort_order=fact.sort_order
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND audit.xmin=current_package_catalog_xid_090()
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_group'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND ((NEW.action='package.group.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision)) OR
			       (NEW.action<>'package.group.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision,'visible',fact.visible)))
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
		) THEN
			RETURN NEW;
		END IF;
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='product' AND EXISTS (
			SELECT 1 FROM package_product_state_facts_090 fact
			JOIN package_products source ON source.id=fact.product_id AND source.revision=fact.revision
			JOIN package_product_versions version
			  ON version.product_id=fact.product_id AND version.revision=fact.revision
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE fact.catalog_sequence=NEW.catalog_sequence
			  AND fact.product_id=NEW.resource_id AND fact.revision=NEW.resource_revision
			  AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
			  AND fact.xmin=current_package_catalog_xid_090()
			  AND source.xmin=current_package_catalog_xid_090()
			  AND source.name=fact.name AND source.enabled=fact.enabled
			  AND source.sort_order=fact.sort_order AND source.spec=fact.spec
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND version.name=fact.name AND version.enabled=fact.enabled
			  AND version.sort_order=fact.sort_order AND version.spec=fact.spec
			  AND version.deleted=fact.deleted
			  AND version.xmin=current_package_catalog_xid_090()
			  AND audit.xmin=current_package_catalog_xid_090()
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_product'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND ((NEW.action='package.product.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision)) OR
			       (NEW.action<>'package.product.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision,'enabled',fact.enabled)))
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
		) THEN
			RETURN NEW;
		END IF;
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='publication' AND EXISTS (
			SELECT 1 FROM package_offer_publication_events event
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE event.catalog_sequence=NEW.catalog_sequence
			  AND event.product_id=NEW.resource_id
			  AND event.lifecycle_revision=NEW.resource_revision
			  AND event.actor_scope_id=NEW.scope_id AND event.actor_user_id=NEW.actor_user_id
			  AND event.xmin=current_package_catalog_xid_090()
			  AND audit.xmin=current_package_catalog_xid_090()
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_product'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND audit.occurred_at=event.occurred_at
			  AND NEW.action=CASE WHEN event.event_type='withdraw'
			      THEN 'package.product.withdraw' ELSE 'package.product.publish' END
			  AND ((event.event_type='withdraw' AND audit.payload=jsonb_build_object(
			        'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision)) OR
			       (event.event_type<>'withdraw' AND audit.payload=jsonb_build_object(
			        'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision,
			        'event_type',event.event_type)))
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
		) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog audit link is immutable and source bound'
			USING ERRCODE = 'P9002';
	END IF;
	RAISE EXCEPTION 'package catalog state is immutable and server assigned'
		USING ERRCODE = 'P9002';
END;
$$;

CREATE TRIGGER package_catalog_watermark_protected_090
BEFORE INSERT OR UPDATE OR DELETE ON package_catalog_commit_watermark_090
FOR EACH ROW EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_catalog_watermark_no_truncate_090
BEFORE TRUNCATE ON package_catalog_commit_watermark_090
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_group_state_facts_protected_090
BEFORE INSERT OR UPDATE OR DELETE ON package_group_state_facts_090
FOR EACH ROW EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_group_state_facts_no_truncate_090
BEFORE TRUNCATE ON package_group_state_facts_090
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_product_state_facts_protected_090
BEFORE INSERT OR UPDATE OR DELETE ON package_product_state_facts_090
FOR EACH ROW EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_product_state_facts_no_truncate_090
BEFORE TRUNCATE ON package_product_state_facts_090
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_catalog_audit_links_protected_090
BEFORE INSERT OR UPDATE OR DELETE ON package_catalog_audit_links_090
FOR EACH ROW EXECUTE FUNCTION protect_package_catalog_state_090();
CREATE TRIGGER package_catalog_audit_links_no_truncate_090
BEFORE TRUNCATE ON package_catalog_audit_links_090
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_catalog_state_090();

REVOKE ALL ON FUNCTION package_offer_spec_publishable_090(jsonb,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION next_package_catalog_sequence_090() FROM PUBLIC;
REVOKE ALL ON FUNCTION current_package_catalog_xid_090() FROM PUBLIC;
