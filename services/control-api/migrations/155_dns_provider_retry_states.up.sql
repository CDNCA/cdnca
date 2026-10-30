LOCK TABLE schema_migrations,access_scopes,dns_zones,dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_155$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>154 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>154 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=154 AND migration_id='154_control_upgrade_systemd_repository' AND
              checksum_sha256='b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a' AND
              down_checksum_sha256='85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='access_scopes'::regclass AND conname='access_scopes_id_tenant_unique'
    ) OR EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='dns_zones'::regclass AND conname='dns_zones_scope_zone_provider_155'
    ) OR to_regclass('dns_provider_retry_states') IS NOT NULL OR
         to_regprocedure('guard_dns_provider_retry_state_scope_155()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 155 requires the exact verified 154 release head'
            USING ERRCODE='P1550';
    END IF;
END;
$migration_155$;

ALTER TABLE dns_zones
    ADD CONSTRAINT dns_zones_scope_zone_provider_155 UNIQUE(scope_id,id,provider_id);

CREATE TABLE dns_provider_retry_states (
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    revision bigint NOT NULL,
    state jsonb NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id,zone_id,provider_id),
    CHECK(revision>0),
    CHECK(jsonb_typeof(state)='object'),
    CHECK(state ? 'Revision'),
    CHECK((state->>'Revision')::bigint=revision),
    CHECK(isfinite(updated_at) AND date_trunc('microseconds',updated_at)=updated_at),
    FOREIGN KEY(tenant_scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,zone_id,provider_id)
        REFERENCES dns_zones(scope_id,id,provider_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,provider_id)
        REFERENCES dns_providers(scope_id,id) ON DELETE RESTRICT
);

CREATE FUNCTION guard_dns_provider_retry_state_scope_155()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    resolved_scope_id uuid;
BEGIN
    SELECT access_scopes.id INTO resolved_scope_id
    FROM access_scopes
    JOIN dns_zones ON dns_zones.scope_id=access_scopes.id AND
                      dns_zones.id=NEW.zone_id AND
                      dns_zones.provider_id=NEW.provider_id
    JOIN dns_providers ON dns_providers.scope_id=access_scopes.id AND
                          dns_providers.id=NEW.provider_id
    WHERE access_scopes.kind='tenant' AND access_scopes.tenant_id=NEW.tenant_id;

    IF resolved_scope_id IS NULL THEN
        RAISE EXCEPTION 'DNS provider retry state tenant, zone, or provider authority mismatch'
            USING ERRCODE='P1551';
    END IF;
    IF NEW.tenant_scope_id IS NOT NULL AND NEW.tenant_scope_id<>resolved_scope_id THEN
        RAISE EXCEPTION 'DNS provider retry state tenant scope conflicts with durable authority'
            USING ERRCODE='P1551';
    END IF;
    NEW.tenant_scope_id:=resolved_scope_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_provider_retry_state_scope_guard_155
BEFORE INSERT OR UPDATE ON dns_provider_retry_states
FOR EACH ROW EXECUTE FUNCTION guard_dns_provider_retry_state_scope_155();

REVOKE ALL ON dns_provider_retry_states FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_dns_provider_retry_state_scope_155() FROM PUBLIC;
