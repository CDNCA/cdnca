LOCK TABLE schema_migrations, nodes, node_line_endpoints, cname_allocations IN ACCESS EXCLUSIVE MODE;

DO $migration_280_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 279 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 279 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=279 AND
        migration_id='279_node_monitoring_overrides' AND
        checksum_sha256='f954c57bdafed2ee7a0381034458ce8171805949d03a74a6db3ccba45cf894ca' AND
        down_checksum_sha256='618c0b4546625d12d1f85da00f786f168256c174a579bd11b8666d8eb2d3bb70' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_serving_holds') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 280 requires the exact verified 279 release head' USING ERRCODE='P2800';
    END IF;
END;
$migration_280_up$;

-- A system hold takes a node out of what customers resolve to without touching
-- admin_state (which revokes the Agent identity). One row per node and source;
-- the node keeps its session and monitoring so the hold can release itself.
CREATE TABLE node_serving_holds (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    source text NOT NULL CHECK (source IN ('availability_monitor', 'auto_disable')),
    held boolean NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    revision bigint NOT NULL CHECK (revision >= 1),
    held_since timestamptz,
    protected_groups integer NOT NULL DEFAULT 0 CHECK (protected_groups >= 0),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    changed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, source),
    CHECK (held = (held_since IS NOT NULL)),
    CHECK (held OR protected_groups = 0),
    CHECK (updated_at >= changed_at)
);

-- Append-only transition log shown in the node monitoring log dialog.
CREATE TABLE node_serving_events (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    source text NOT NULL CHECK (source IN ('availability_monitor', 'auto_disable')),
    event text NOT NULL CHECK (event IN ('held', 'released', 'protected', 'protection_cleared')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    hold_revision bigint NOT NULL CHECK (hold_revision >= 1),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    occurred_at timestamptz NOT NULL,
    UNIQUE (node_id, source, hold_revision)
);
CREATE INDEX node_serving_events_node_time_280_idx ON node_serving_events(node_id, occurred_at DESC, id DESC);

CREATE FUNCTION protect_node_serving_hold_280() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'node serving holds are never deleted' USING ERRCODE='P2801';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 THEN
            RAISE EXCEPTION 'node serving hold must start at revision 1' USING ERRCODE='P2802';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.node_id, NEW.source) IS DISTINCT FROM ROW(OLD.node_id, OLD.source) OR
       NEW.updated_at < OLD.updated_at OR
       (NEW.revision <> OLD.revision AND NEW.revision <> OLD.revision + 1) OR
       (NEW.revision = OLD.revision AND ROW(NEW.held, NEW.reason_code, NEW.held_since, NEW.protected_groups > 0, NEW.changed_at)
            IS DISTINCT FROM ROW(OLD.held, OLD.reason_code, OLD.held_since, OLD.protected_groups > 0, OLD.changed_at)) THEN
        RAISE EXCEPTION 'node serving hold transition must advance its revision by one' USING ERRCODE='P2802';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER node_serving_holds_protect_280
BEFORE INSERT OR UPDATE OR DELETE ON node_serving_holds
FOR EACH ROW EXECUTE FUNCTION protect_node_serving_hold_280();
CREATE TRIGGER node_serving_holds_no_truncate_280
BEFORE TRUNCATE ON node_serving_holds
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_serving_hold_280();

CREATE FUNCTION protect_node_serving_event_280() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'node serving events are append-only' USING ERRCODE='P2801';
END;
$$;
CREATE TRIGGER node_serving_events_append_only_280
BEFORE UPDATE OR DELETE ON node_serving_events
FOR EACH ROW EXECUTE FUNCTION protect_node_serving_event_280();
CREATE TRIGGER node_serving_events_no_truncate_280
BEFORE TRUNCATE ON node_serving_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_serving_event_280();

-- Serving eligibility of each line endpoint: admin enabled (endpoint enabled
-- and its node not disabled/retired/pending) and not held by any system source.
-- Fail-open per address family: when every admin-enabled endpoint of a family
-- is held, all of them keep serving and are reported as protected, so a line
-- group never loses its last A or AAAA target.
CREATE VIEW node_line_endpoint_serving AS
WITH classified AS (
    SELECT endpoint.tenant_scope_id, endpoint.line_group_id, endpoint.config_revision,
           endpoint.id AS endpoint_id, endpoint.node_id, endpoint.address,
           family(endpoint.address) AS address_family,
           (endpoint.enabled AND (endpoint.node_id IS NULL OR node.admin_state IN ('active', 'draining'))) AS admin_enabled,
           EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id = endpoint.node_id AND hold.held) AS held
    FROM node_line_endpoints endpoint
    LEFT JOIN nodes node ON node.id = endpoint.node_id
), counted AS (
    SELECT classified.*,
           count(*) FILTER (WHERE admin_enabled AND NOT held) OVER (
               PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family) AS family_serving
    FROM classified
)
SELECT tenant_scope_id, line_group_id, config_revision, endpoint_id, node_id, address, address_family,
       admin_enabled, held,
       (admin_enabled AND (NOT held OR family_serving = 0)) AS serving,
       (admin_enabled AND held AND family_serving = 0) AS protected
FROM counted;

-- A retarget republishes the A/AAAA values of an already allocated CNAME
-- hostname when the serving endpoints of its line group change. The hostname,
-- claim and allocation revision are untouched; only DNS values move.
CREATE TABLE dns_cname_retargets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    base_job_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    site_id uuid NOT NULL,
    node_group_id uuid NOT NULL,
    node_group_revision bigint NOT NULL CHECK (node_group_revision > 0),
    zone_id uuid NOT NULL,
    zone_revision bigint NOT NULL CHECK (zone_revision > 0),
    owner_name text NOT NULL CHECK (char_length(owner_name) BETWEEN 1 AND 253),
    target_a text[] NOT NULL DEFAULT '{}',
    target_aaaa text[] NOT NULL DEFAULT '{}',
    ttl integer NOT NULL CHECK (ttl = 300),
    target_digest text NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128 AND request_id !~ '[[:cntrl:]]'),
    state text NOT NULL CHECK (state IN ('pending', 'applying', 'committed', 'failed', 'superseded')),
    child_task_id uuid,
    child_task_revision bigint,
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, allocation_id, sequence),
    FOREIGN KEY (tenant_scope_id, tenant_id) REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, allocation_id) REFERENCES cname_allocations(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, base_job_id) REFERENCES background_jobs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_group_id, node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, zone_id) REFERENCES dns_zones(scope_id, id) ON DELETE RESTRICT,
    CHECK (cardinality(target_a) + cardinality(target_aaaa) > 0),
    CHECK ((child_task_id IS NULL) = (child_task_revision IS NULL)),
    CHECK ((state = 'failed') = (failure_code IS NOT NULL)),
    CHECK (state NOT IN ('applying', 'committed') OR child_task_id IS NOT NULL),
    CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX dns_cname_retargets_inflight_280_idx
    ON dns_cname_retargets(tenant_scope_id, allocation_id) WHERE state IN ('pending', 'applying');
CREATE INDEX dns_cname_retargets_open_280_idx
    ON dns_cname_retargets(updated_at, id) WHERE state IN ('pending', 'applying');

CREATE FUNCTION protect_dns_cname_retarget_280() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'CNAME retarget facts are durable' USING ERRCODE='P2801';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.child_task_id IS NOT NULL THEN
            RAISE EXCEPTION 'CNAME retarget must start pending' USING ERRCODE='P2802';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id, NEW.tenant_id, NEW.tenant_scope_id, NEW.allocation_id, NEW.base_job_id, NEW.sequence,
           NEW.site_id, NEW.node_group_id, NEW.node_group_revision, NEW.zone_id, NEW.zone_revision,
           NEW.owner_name, NEW.target_a, NEW.target_aaaa, NEW.ttl, NEW.target_digest, NEW.actor_user_id,
           NEW.request_id, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.tenant_scope_id, OLD.allocation_id, OLD.base_job_id, OLD.sequence,
           OLD.site_id, OLD.node_group_id, OLD.node_group_revision, OLD.zone_id, OLD.zone_revision,
           OLD.owner_name, OLD.target_a, OLD.target_aaaa, OLD.ttl, OLD.target_digest, OLD.actor_user_id,
           OLD.request_id, OLD.created_at) OR
       OLD.state IN ('committed', 'failed', 'superseded') OR NEW.updated_at < OLD.updated_at OR
       (OLD.child_task_id IS NOT NULL AND NEW.child_task_id IS DISTINCT FROM OLD.child_task_id) OR
       NOT ((OLD.state = 'pending' AND NEW.state IN ('pending', 'applying', 'failed', 'superseded')) OR
            (OLD.state = 'applying' AND NEW.state IN ('applying', 'committed', 'failed', 'superseded'))) THEN
        RAISE EXCEPTION 'CNAME retarget transition is invalid' USING ERRCODE='P2802';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dns_cname_retargets_protect_280
BEFORE INSERT OR UPDATE OR DELETE ON dns_cname_retargets
FOR EACH ROW EXECUTE FUNCTION protect_dns_cname_retarget_280();
CREATE TRIGGER dns_cname_retargets_no_truncate_280
BEFORE TRUNCATE ON dns_cname_retargets
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_cname_retarget_280();

REVOKE ALL ON FUNCTION protect_node_serving_hold_280() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_node_serving_event_280() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_dns_cname_retarget_280() FROM PUBLIC;
REVOKE ALL ON node_line_endpoint_serving FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_serving_holds TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON node_serving_events TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON dns_cname_retargets TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT ON node_line_endpoint_serving TO cdnca_control_app, cdnca_control_runtime;
