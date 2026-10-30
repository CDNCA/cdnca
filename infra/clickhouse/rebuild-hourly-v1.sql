CREATE TABLE {run_marker:Identifier}
(
    owner String,
    lock_token String
)
ENGINE = ReplacingMergeTree
ORDER BY tuple();

INSERT INTO {run_marker:Identifier} VALUES ({owner:String}, {lock_token:String});

SELECT throwIf(
    uniqExact(tuple(owner, lock_token)) != 1 OR any(owner) != {owner:String} OR
        any(lock_token) != {lock_token:String},
    'analytics rebuild owner does not match'
)
FROM {run_marker:Identifier};

CREATE TABLE {access_shadow:Identifier} AS access_hourly_facts_v1;
CREATE TABLE {security_shadow:Identifier} AS security_hourly_facts_v1;

CREATE MATERIALIZED VIEW {access_catchup:Identifier}
TO {access_shadow:Identifier} AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    status_code,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events;

CREATE MATERIALIZED VIEW {security_catchup:Identifier}
TO {security_shadow:Identifier} AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    event_type,
    action,
    request_bytes,
    response_bytes,
    ingested_at,
    event_count AS requests
FROM security_events;

INSERT INTO {access_shadow:Identifier}
SELECT * FROM access_hourly_facts_v1 FINAL;

INSERT INTO {security_shadow:Identifier}
SELECT * FROM security_hourly_facts_v1 FINAL;

INSERT INTO {access_shadow:Identifier}
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC'),
    site_id,
    node_id,
    status_code,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events FINAL;

INSERT INTO {security_shadow:Identifier}
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC'),
    site_id,
    node_id,
    event_type,
    action,
    request_bytes,
    response_bytes,
    ingested_at,
    event_count AS requests
FROM security_events FINAL;

OPTIMIZE TABLE {access_shadow:Identifier} FINAL;
OPTIMIZE TABLE {security_shadow:Identifier} FINAL;

SELECT throwIf({fail_after_backfill:UInt8} = 1, 'injected analytics rebuild failure after backfill');

EXCHANGE TABLES access_hourly_facts_v1 AND {access_shadow:Identifier};
SELECT throwIf(
    {fail_after_access_exchange:UInt8} = 1,
    'injected analytics rebuild failure after access exchange'
);
EXCHANGE TABLES security_hourly_facts_v1 AND {security_shadow:Identifier};

DROP VIEW {access_catchup:Identifier};
DROP VIEW {security_catchup:Identifier};
DROP TABLE {access_shadow:Identifier} SYNC;
DROP TABLE {security_shadow:Identifier} SYNC;
DROP TABLE {run_marker:Identifier} SYNC;
