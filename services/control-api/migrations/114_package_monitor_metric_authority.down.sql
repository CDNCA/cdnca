LOCK TABLE schema_migrations,
    package_monitor_metric_observations_114,
    package_monitor_config_installations_114,
    package_monitor_site_subscription_bindings_114,
    package_monitor_policy_versions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 114 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 114 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=114 AND migration_id='114_package_monitor_metric_authority'
          AND checksum_sha256='438ff725214147c5bd10462396d715a47ba29aa554c7e180ff7a48b7bb37e5a3'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=113 AND migration_id='113_cname_authority'
          AND checksum_sha256='ac4716d79decdb1076dbc19a5bf9ac9400d997f198cd56a8639b3d1924c12ccb'
          AND down_checksum_sha256='0928a9f3a9d93df1917fe32b2a4c0b5c406cbb7fdb0f66fe84523404522fe5a5'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 114 rollback requires the exact verified 114 head'
            USING ERRCODE='P1140';
    END IF;

    IF EXISTS (SELECT 1 FROM package_monitor_metric_observations_114) OR
       EXISTS (SELECT 1 FROM package_monitor_config_installations_114) OR
       EXISTS (SELECT 1 FROM package_monitor_site_subscription_bindings_114) THEN
        RAISE EXCEPTION 'migration 114 rollback would discard package monitor metric authority facts'
            USING ERRCODE='P1145';
    END IF;
END;
$$;

DROP TRIGGER prevent_package_monitor_metric_truncate_114 ON package_monitor_metric_observations_114;
DROP TRIGGER package_monitor_metric_observations_immutable_114 ON package_monitor_metric_observations_114;
DROP TRIGGER package_monitor_config_installations_no_truncate_114 ON package_monitor_config_installations_114;
DROP TRIGGER package_monitor_config_installations_immutable_114 ON package_monitor_config_installations_114;
DROP TRIGGER package_monitor_site_bindings_no_truncate_114 ON package_monitor_site_subscription_bindings_114;
DROP TRIGGER package_monitor_site_bindings_immutable_114 ON package_monitor_site_subscription_bindings_114;

DROP FUNCTION package_monitor_commit_metric_observation_114(uuid,uuid,uuid,bigint,text,text,numeric,timestamptz,timestamptz,bytea,bigint,timestamptz);
DROP FUNCTION package_monitor_resolve_period_114(timestamptz,timestamptz,text,text,integer,timestamptz);

DROP TABLE package_monitor_metric_observations_114;
DROP TABLE package_monitor_config_installations_114;
DROP TABLE package_monitor_site_subscription_bindings_114;

DROP FUNCTION package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz);
DROP FUNCTION guard_package_monitor_metric_authority_114();

ALTER TABLE package_monitor_policy_versions
    DROP CONSTRAINT package_monitor_policy_metric_identity_114_key;

DROP SEQUENCE package_monitor_metric_watermark_114_seq;
