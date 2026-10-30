LOCK TABLE schema_migrations, package_subscription_entitlement_versions IN ACCESS EXCLUSIVE MODE;

DO $migration_140$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 140 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 140 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 140 AND migration_id = '140_package_subscription_manual_open' AND
              checksum_sha256 = 'a89707a1033c0b192569081af1119ca1e075016a06cdd40df71fb8d7d28d5489' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 139 AND migration_id = '139_l4_line_switches' AND
              checksum_sha256 = '2ad9c5bdb52acc550197197113b581ea36e123826275121f68c48e687cdbc680' AND
              down_checksum_sha256 = '96d294cbae3ba56fa21ba0ec25ee0fec2a3e554dd26049c2fed7a4f279415d4b' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 140 rollback requires the verified 140 head'
            USING ERRCODE = 'P1400';
    END IF;
    IF EXISTS (
        SELECT 1 FROM package_subscription_entitlement_versions WHERE operation='manual_open'
    ) THEN
        RAISE EXCEPTION 'migration 140 rollback would discard manual subscription facts'
            USING ERRCODE = 'P1402';
    END IF;
END;
$migration_140$;

ALTER TABLE package_subscription_entitlement_versions
    DROP CONSTRAINT package_entitlement_operation_140_check,
    DROP CONSTRAINT package_entitlement_source_order_140_check,
    ADD CONSTRAINT package_entitlement_operation_check CHECK (operation IN (
        'migration_backfill', 'purchase', 'renew', 'upgrade', 'downgrade', 'refund', 'void'
    )),
    ADD CONSTRAINT package_entitlement_source_order_check CHECK (
        (operation = 'migration_backfill') = (source_order_id IS NULL)
    );
