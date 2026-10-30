LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_590_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 589 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 589 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=589 AND
        migration_id='589_site_origin_tls_no_verify' AND
        checksum_sha256='cdcef347d4b344cd7b1bf6c60e01570654867d9694b5d021f45b4378c2f715e5' AND
        down_checksum_sha256='f076ba607c020768412f2307de8d8d94d41453a83cce8534fbd489ebdebb3c53' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='installation_allowed'
       ) THEN
        RAISE EXCEPTION 'migration 590 requires the exact verified 589 release head' USING ERRCODE='P5900';
    END IF;
END;
$migration_590_up$;

-- 590 (r136 fix-nrecovery2, placeholder: renumber at the merge). The
-- installation ban serving state of the latest heartbeat
-- (EdgeRuntimeStatus.installation_serving): what the documents allow
-- (allowed), what the node actually serves (serving, stopped_at) and its last
-- recovery (result, time, the status that had stopped it, failures in a
-- row). All NULL: the node does not run the installation ban or did not
-- report it.
ALTER TABLE node_presence
    ADD COLUMN installation_allowed text
        CONSTRAINT node_presence_installation_allowed_590_check
        CHECK (installation_allowed IN ('serving', 'banned', 'service_ticket_expired', 'no_ticket')),
    ADD COLUMN installation_serving text
        CONSTRAINT node_presence_installation_serving_590_check
        CHECK (installation_serving IN ('serving', 'stopped', 'stop_failed', 'resume_failed')),
    ADD COLUMN installation_stopped_at timestamptz
        CONSTRAINT node_presence_installation_stopped_at_590_check CHECK (isfinite(installation_stopped_at)),
    ADD COLUMN installation_recovery_result text
        CONSTRAINT node_presence_installation_recovery_result_590_check
        CHECK (installation_recovery_result IN ('resumed', 'failed')),
    ADD COLUMN installation_recovery_at timestamptz
        CONSTRAINT node_presence_installation_recovery_at_590_check CHECK (isfinite(installation_recovery_at)),
    ADD COLUMN installation_recovery_cause text
        CONSTRAINT node_presence_installation_recovery_cause_590_check
        CHECK (installation_recovery_cause IN ('banned', 'service_ticket_expired', 'no_ticket')),
    ADD COLUMN installation_recovery_failures integer
        CONSTRAINT node_presence_installation_recovery_failures_590_check
        CHECK (installation_recovery_failures BETWEEN 0 AND 65536),
    ADD CONSTRAINT node_presence_installation_serving_590_shape_check CHECK (
        (installation_allowed IS NULL) = (installation_serving IS NULL) AND
        (installation_serving IS NOT NULL OR (installation_stopped_at IS NULL AND installation_recovery_result IS NULL)) AND
        ((installation_recovery_result IS NULL) = (installation_recovery_at IS NULL) AND
         (installation_recovery_result IS NULL) = (installation_recovery_cause IS NULL) AND
         (installation_recovery_result IS NULL) = (installation_recovery_failures IS NULL))
    );
