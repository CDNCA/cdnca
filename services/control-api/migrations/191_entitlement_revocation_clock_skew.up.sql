LOCK TABLE schema_migrations, control_entitlement_revocation_lkg IN ACCESS EXCLUSIVE MODE;

DO $migration_191$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 190 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 190 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=190 AND migration_id='190_platform_account_recovery' AND
              checksum_sha256='899fb7cf71bcfea6ff7cfd4760a3792e0c002bae39961e8b9acf433de5098799' AND
              down_checksum_sha256='d3af7a098d777207b227ccd4be3a52461cf0b74349e7448390180ba207e01766' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 191 requires the exact verified 190 release head'
            USING ERRCODE='P1910';
    END IF;
END;
$migration_191$;

CREATE TABLE entitlement_revocation_clock_skew_191_backup (
    singleton boolean PRIMARY KEY CHECK (singleton),
    definition text NOT NULL
);

INSERT INTO entitlement_revocation_clock_skew_191_backup(singleton, definition)
VALUES (true, pg_get_functiondef('guard_control_entitlement_revocation_lkg_084()'::regprocedure));

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT backup.definition INTO definition
    FROM entitlement_revocation_clock_skew_191_backup backup
    WHERE backup.singleton=true;
    before_definition := definition;
    definition := replace(definition,
        $$IF physical_now < NEW.issued_at OR physical_now >= NEW.expires_at THEN$$,
        $$IF physical_now < NEW.issued_at - interval '2 seconds' OR physical_now >= NEW.expires_at THEN$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 191 physical validity marker is missing' USING ERRCODE='P1911';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$NEW.accepted_at := physical_now;$$,
        $$NEW.accepted_at := GREATEST(physical_now, NEW.issued_at);$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 191 accepted_at marker is missing' USING ERRCODE='P1911';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DROP TABLE entitlement_revocation_clock_skew_191_backup;
