LOCK TABLE schema_migrations, package_subscription_entitlement_versions IN ACCESS EXCLUSIVE MODE;

DO $migration_140$
DECLARE
    operation_constraint text;
    source_order_constraint text;
    operation_attnum smallint;
    source_order_attnum smallint;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 139 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 139 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 139 AND migration_id = '139_l4_line_switches' AND
              checksum_sha256 = '2ad9c5bdb52acc550197197113b581ea36e123826275121f68c48e687cdbc680' AND
              down_checksum_sha256 = '96d294cbae3ba56fa21ba0ec25ee0fec2a3e554dd26049c2fed7a4f279415d4b' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 140 requires the exact verified 139 release head'
            USING ERRCODE = 'P1400';
    END IF;

    SELECT attnum INTO operation_attnum
    FROM pg_attribute
    WHERE attrelid = 'package_subscription_entitlement_versions'::regclass AND attname = 'operation';
    SELECT attnum INTO source_order_attnum
    FROM pg_attribute
    WHERE attrelid = 'package_subscription_entitlement_versions'::regclass AND attname = 'source_order_id';

    SELECT conname INTO operation_constraint
    FROM pg_constraint
    WHERE conrelid = 'package_subscription_entitlement_versions'::regclass AND contype = 'c' AND
          conkey = ARRAY[operation_attnum]::smallint[];
    SELECT conname INTO source_order_constraint
    FROM pg_constraint
    WHERE conrelid = 'package_subscription_entitlement_versions'::regclass AND contype = 'c' AND
          conkey @> ARRAY[operation_attnum, source_order_attnum]::smallint[] AND
          cardinality(conkey) = 2;

    IF operation_constraint IS NULL OR source_order_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 140 requires the verified package entitlement constraints'
            USING ERRCODE = 'P1401';
    END IF;
    EXECUTE format('ALTER TABLE package_subscription_entitlement_versions DROP CONSTRAINT %I', operation_constraint);
    EXECUTE format('ALTER TABLE package_subscription_entitlement_versions DROP CONSTRAINT %I', source_order_constraint);
END;
$migration_140$;

ALTER TABLE package_subscription_entitlement_versions
    ADD CONSTRAINT package_entitlement_operation_140_check CHECK (operation IN (
        'migration_backfill', 'manual_open', 'purchase', 'renew', 'upgrade', 'downgrade', 'refund', 'void'
    )),
    ADD CONSTRAINT package_entitlement_source_order_140_check CHECK (
        (operation IN ('migration_backfill','manual_open')) = (source_order_id IS NULL)
    );
