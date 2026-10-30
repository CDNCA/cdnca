CREATE TABLE site_origin_pools (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    balance_method text NOT NULL DEFAULT 'round_robin' CHECK (
        balance_method IN ('round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random')
    ),
    failover_tries smallint NOT NULL DEFAULT 1 CHECK (failover_tries BETWEEN 1 AND 32),
    connect_timeout_ms integer NOT NULL DEFAULT 3000 CHECK (connect_timeout_ms BETWEEN 50 AND 30000),
    read_timeout_ms integer NOT NULL DEFAULT 30000 CHECK (read_timeout_ms BETWEEN 100 AND 300000),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE site_origins (
    site_id uuid NOT NULL REFERENCES site_origin_pools(site_id) ON DELETE CASCADE,
    position smallint NOT NULL CHECK (position BETWEEN 1 AND 32),
    host text NOT NULL CHECK (
        host = lower(btrim(host)) AND
        char_length(host) BETWEEN 1 AND 253 AND
        host !~ '[[:space:]/?#@]'
    ),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    weight smallint NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 100),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (site_id, position),
    UNIQUE (site_id, host, port)
);

CREATE TABLE site_origin_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX site_origin_write_requests_scope_created_idx
    ON site_origin_write_requests (actor_scope_id, created_at DESC);

INSERT INTO site_origin_pools (site_id, updated_at)
SELECT id, updated_at FROM sites;

WITH legacy AS (
    SELECT
        s.id AS site_id,
        index::smallint AS position,
        lower(btrim(s.origin_hosts[index])) AS host,
        lower(btrim(s.origins[index])) AS endpoint
    FROM sites s
    CROSS JOIN LATERAL generate_subscripts(s.origins, 1) AS index
), parsed AS (
    SELECT
        site_id,
        position,
        host,
        CASE
            WHEN endpoint = host OR endpoint = '[' || host || ']' THEN 80
            WHEN position(':' IN host) > 0 AND
                 starts_with(endpoint, '[' || host || ']:') AND
                 substring(endpoint FROM char_length(host) + 4) ~ '^[0-9]+$'
                THEN substring(endpoint FROM char_length(host) + 4)::integer
            WHEN position(':' IN host) = 0 AND
                 starts_with(endpoint, host || ':') AND
                 substring(endpoint FROM char_length(host) + 2) ~ '^[0-9]+$'
                THEN substring(endpoint FROM char_length(host) + 2)::integer
            ELSE 0
        END AS port
    FROM legacy
)
INSERT INTO site_origins (site_id, position, host, port, weight, enabled)
SELECT site_id, position, host, port, 1, true
FROM parsed
ORDER BY site_id, position;

WITH compatibility AS (
    SELECT
        site_id,
        array_agg(
            CASE
                WHEN port = 80 THEN host
                WHEN position(':' IN host) > 0 THEN '[' || host || ']:' || port::text
                ELSE host || ':' || port::text
            END
            ORDER BY position
        ) AS origins,
        array_agg(host ORDER BY position) AS origin_hosts
    FROM site_origins
    GROUP BY site_id
)
UPDATE sites s
SET origins = compatibility.origins,
    origin_hosts = compatibility.origin_hosts
FROM compatibility
WHERE compatibility.site_id = s.id;

CREATE FUNCTION validate_site_origin_pool(target_site_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    pool_failover smallint;
    origin_count integer;
    enabled_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sites WHERE id = target_site_id) THEN
        RETURN;
    END IF;

    SELECT failover_tries
    INTO pool_failover
    FROM site_origin_pools
    WHERE site_id = target_site_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'site origin pool is required for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE enabled)
    INTO origin_count, enabled_count
    FROM site_origins
    WHERE site_id = target_site_id;

    IF origin_count < 1 OR origin_count > 32 OR enabled_count < 1 OR pool_failover > enabled_count THEN
        RAISE EXCEPTION 'site origin pool invariant failed for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION check_site_origin_pool_from_site() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM validate_site_origin_pool(NEW.id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION check_site_origin_pool_from_pool() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM validate_site_origin_pool(COALESCE(NEW.site_id, OLD.site_id));
    RETURN NULL;
END;
$$;

CREATE FUNCTION check_site_origin_pool_from_origin() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.site_id IS DISTINCT FROM NEW.site_id THEN
        PERFORM validate_site_origin_pool(OLD.site_id);
    END IF;
    PERFORM validate_site_origin_pool(COALESCE(NEW.site_id, OLD.site_id));
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER sites_require_origin_pool
AFTER INSERT ON sites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION check_site_origin_pool_from_site();

CREATE CONSTRAINT TRIGGER site_origin_pools_validate
AFTER INSERT OR UPDATE OR DELETE ON site_origin_pools
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION check_site_origin_pool_from_pool();

CREATE CONSTRAINT TRIGGER site_origins_validate
AFTER INSERT OR UPDATE OR DELETE ON site_origins
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION check_site_origin_pool_from_origin();
