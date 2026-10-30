LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_411_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 410 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 410 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=410 AND
        migration_id='410_autodefense_baseline_drift' AND
        checksum_sha256='12e3716efa11045662977648da7b67910e01e633ce2e6acbeb880f7cdf2de28b' AND
        down_checksum_sha256='79411f1082cef12ebc7d14aed75fb1efc675df0bee3c42b5823ded04bb1d6ab3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.autodefense_node_snapshots') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 411 requires the exact verified 410 release head' USING ERRCODE='P4110';
    END IF;
END;
$migration_411_up$;

-- 411（r136 ad-09，占位号，合入时改号）。AutoDefenseCommand delivery per
-- node (ADR 0010 section 8.2; node autonomy, user 10-19 06:20: the snapshot
-- carries settings, overlays and module configuration only, never a
-- baseline). One row per node that was ever sent a snapshot:
--   revision / issued_at / content_sha256 / sites: the newest revision the
--     control plane built (issued_at rebuilds the identical signed bytes for
--     a republish; content_sha256 is the digest of the node state without
--     revision and issue time, so an unchanged state is not a new revision);
--   published_at: the last time it was handed to the gateway stream;
--   receipt_*: the newest receipt the node sent (any revision). The site
--     page reads receipt_error='not_supported' as "this node does not run
--     automatic defense" (F4; the agent declares AUTO_DEFENSE everywhere and
--     refuses snapshots it cannot run).
CREATE TABLE autodefense_node_snapshots (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 1125899906842624),
    issued_at timestamptz NOT NULL CHECK (isfinite(issued_at)),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    sites integer NOT NULL CHECK (sites >= 0),
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    receipt_revision bigint CHECK (receipt_revision IS NULL OR receipt_revision > 0),
    receipt_applied boolean,
    receipt_error text CHECK (receipt_error IS NULL OR receipt_error IN ('untrusted_signature', 'invalid_snapshot',
        'wrong_node', 'stale_revision', 'incomplete_parts', 'runtime_unavailable', 'not_supported')),
    receipt_sites integer CHECK (receipt_sites IS NULL OR receipt_sites >= 0),
    receipt_signatures integer CHECK (receipt_signatures IS NULL OR receipt_signatures >= 0),
    receipt_mitigations integer CHECK (receipt_mitigations IS NULL OR receipt_mitigations >= 0),
    receipt_at timestamptz CHECK (receipt_at IS NULL OR isfinite(receipt_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    CHECK ((receipt_revision IS NULL) = (receipt_applied IS NULL) AND (receipt_revision IS NULL) = (receipt_at IS NULL)),
    CHECK (receipt_applied IS NULL OR (receipt_applied = (receipt_error IS NULL))),
    CHECK ((receipt_applied IS TRUE) = (receipt_sites IS NOT NULL AND receipt_signatures IS NOT NULL AND receipt_mitigations IS NOT NULL))
);

REVOKE ALL ON autodefense_node_snapshots FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON autodefense_node_snapshots TO cdnca_control_app, cdnca_control_runtime;
