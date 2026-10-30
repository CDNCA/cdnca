LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_150$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 149 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 149 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 149 AND migration_id = '149_api_key_pepper_rotation' AND
              checksum_sha256 = '32099eee305e8bd90c0b4e86392b3b7859267f9d9dd4aa5c379c8b6d1d028336' AND
              down_checksum_sha256 = '465b9544a68a59997217e1e24b9154637fcf463afc838cb14211c0e2dc3dac90' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('node_metric_samples') IS NOT NULL OR
         to_regclass('node_metric_latest') IS NOT NULL OR
         to_regprocedure('guard_node_metric_sequence_150()') IS NOT NULL OR
         to_regprocedure('protect_node_metric_sample_150()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 150 requires the exact verified 149 release head'
            USING ERRCODE = 'P1500';
    END IF;
END;
$migration_150$;

CREATE TABLE node_metric_samples (
    event_id uuid PRIMARY KEY CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    config_revision bigint NOT NULL CHECK (config_revision > 0),
    publication_sequence bigint NOT NULL CHECK (publication_sequence > 0),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    metrics_known boolean NOT NULL,
    cpu_percent double precision,
    memory_used_bytes bigint,
    memory_total_bytes bigint,
    active_connections bigint,
    rx_bandwidth_bps bigint,
    tx_bandwidth_bps bigint,
    puback_stream text NOT NULL CHECK (puback_stream = 'NODE_MONITORING_STATUS'),
    puback_sequence bigint NOT NULL CHECK (puback_sequence > 0),
    consumer_durable text NOT NULL CHECK (consumer_durable = 'control_api_node_metrics'),
    consumer_sequence bigint NOT NULL CHECK (consumer_sequence > 0),
    num_delivered bigint NOT NULL CHECK (num_delivered > 0),
    wire_sha256 bytea NOT NULL CHECK (octet_length(wire_sha256) = 32),
    ingested_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK (isfinite(ingested_at)),
    CHECK (
        (NOT metrics_known AND cpu_percent IS NULL AND memory_used_bytes IS NULL AND
         memory_total_bytes IS NULL AND active_connections IS NULL AND
         rx_bandwidth_bps IS NULL AND tx_bandwidth_bps IS NULL) OR
        (metrics_known AND cpu_percent IS NOT NULL AND cpu_percent BETWEEN 0 AND 100 AND
         cpu_percent <> 'NaN'::double precision AND memory_used_bytes IS NOT NULL AND
         memory_total_bytes IS NOT NULL AND memory_total_bytes > 0 AND
         memory_used_bytes BETWEEN 0 AND memory_total_bytes AND active_connections IS NOT NULL AND
         active_connections >= 0 AND rx_bandwidth_bps IS NOT NULL AND rx_bandwidth_bps >= 0 AND
         tx_bandwidth_bps IS NOT NULL AND tx_bandwidth_bps >= 0)
    ),
    UNIQUE (node_id, publication_sequence),
    UNIQUE (puback_stream, puback_sequence)
);

CREATE INDEX node_metric_samples_latest_150_idx
    ON node_metric_samples(node_id, publication_sequence DESC);
CREATE INDEX node_metric_samples_observed_150_idx
    ON node_metric_samples(observed_at DESC, node_id);

CREATE FUNCTION guard_node_metric_sequence_150()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.node_id::text, 150));
    IF EXISTS (
        SELECT 1 FROM node_metric_samples
        WHERE event_id = NEW.event_id AND node_id = NEW.node_id AND
              publication_sequence = NEW.publication_sequence AND
              puback_stream = NEW.puback_stream AND puback_sequence = NEW.puback_sequence AND
              wire_sha256 = NEW.wire_sha256
    ) THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_metric_samples
        WHERE node_id = NEW.node_id AND publication_sequence > NEW.publication_sequence
    ) THEN
        RAISE EXCEPTION 'node metric publication sequence is stale'
            USING ERRCODE = 'P1501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_metric_sequence_guard_150
BEFORE INSERT ON node_metric_samples
FOR EACH ROW EXECUTE FUNCTION guard_node_metric_sequence_150();

CREATE FUNCTION protect_node_metric_sample_150()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node metric samples are append-only'
        USING ERRCODE = 'P1502';
END;
$$;

CREATE TRIGGER node_metric_samples_immutable_150
BEFORE UPDATE OR DELETE OR TRUNCATE ON node_metric_samples
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_metric_sample_150();

CREATE VIEW node_metric_latest AS
SELECT DISTINCT ON (node_id)
    event_id, request_id, node_id, schema_version, config_revision, publication_sequence,
    observed_at, metrics_known, cpu_percent, memory_used_bytes, memory_total_bytes,
    active_connections, rx_bandwidth_bps, tx_bandwidth_bps, puback_stream,
    puback_sequence, consumer_durable, consumer_sequence, num_delivered, wire_sha256, ingested_at
FROM node_metric_samples
ORDER BY node_id, publication_sequence DESC;

REVOKE ALL ON node_metric_samples, node_metric_latest FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_node_metric_sequence_150() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_node_metric_sample_150() FROM PUBLIC;
