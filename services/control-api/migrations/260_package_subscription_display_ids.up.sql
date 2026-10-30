LOCK TABLE schema_migrations, package_subscriptions IN ACCESS EXCLUSIVE MODE;

DO $migration_260_up_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 259 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 259 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 259 AND migration_id = '259_certificate_defaults_runtime_grants' AND
              checksum_sha256 = 'd1bbefc1a232c015f3d4e072b528eb1f6202bdd5e43a7b4f4a544e3720105a65' AND
              down_checksum_sha256 = 'ce7378be178001203d55cdf7d7babf8a673fb1020904ace759f79b9313d64273' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 260 requires the exact verified 259 release head'
            USING ERRCODE = 'P2600';
    END IF;
END;
$migration_260_up_head$;

CREATE TABLE package_subscription_display_ids (
    subscription_id uuid PRIMARY KEY REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE NOT NULL CHECK (display_id > 0)
);

INSERT INTO package_subscription_display_ids(subscription_id, display_id)
OVERRIDING SYSTEM VALUE
SELECT id, row_number() OVER (ORDER BY created_at, id)
FROM package_subscriptions;

DO $migration_260_sequence$
DECLARE
    highest_id bigint;
BEGIN
    SELECT max(display_id) INTO highest_id FROM package_subscription_display_ids;
    IF highest_id IS NOT NULL THEN
        PERFORM setval(
            format('%I.package_subscription_display_ids_display_id_seq', current_schema())::regclass,
            highest_id,
            true
        );
    END IF;
END;
$migration_260_sequence$;

-- Bind the relation at installation time, including in schema-isolated tests.
-- A caller-controlled search_path must never redirect this privileged insert.
DO $migration_260_allocator$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.assign_package_subscription_display_id_260()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $body$
        BEGIN
            INSERT INTO %I.package_subscription_display_ids(subscription_id) VALUES (NEW.id);
            RETURN NEW;
        END;
        $body$;
    $ddl$, current_schema(), current_schema());
END;
$migration_260_allocator$;

CREATE TRIGGER package_subscriptions_assign_display_id_260
AFTER INSERT ON package_subscriptions
FOR EACH ROW EXECUTE FUNCTION assign_package_subscription_display_id_260();

CREATE FUNCTION protect_package_subscription_display_ids_260()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'package subscription display IDs are immutable'
        USING ERRCODE = 'P2601';
END;
$$;

CREATE TRIGGER package_subscription_display_ids_immutable_260
BEFORE UPDATE OR DELETE ON package_subscription_display_ids
FOR EACH ROW EXECUTE FUNCTION protect_package_subscription_display_ids_260();

CREATE TRIGGER package_subscription_display_ids_no_truncate_260
BEFORE TRUNCATE ON package_subscription_display_ids
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_subscription_display_ids_260();

REVOKE ALL ON FUNCTION assign_package_subscription_display_id_260() FROM PUBLIC, cdnca_control_app;
REVOKE ALL ON FUNCTION protect_package_subscription_display_ids_260() FROM PUBLIC, cdnca_control_app;
REVOKE ALL ON package_subscription_display_ids FROM PUBLIC, cdnca_control_app;
REVOKE ALL ON SEQUENCE package_subscription_display_ids_display_id_seq FROM PUBLIC, cdnca_control_app;
GRANT SELECT ON package_subscription_display_ids TO cdnca_control_app;
