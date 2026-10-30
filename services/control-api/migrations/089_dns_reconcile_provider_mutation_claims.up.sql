LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_operations,
    dns_reconcile_tasks,
    sites,
    dns_zones,
    dns_providers
IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 88 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 88 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 88
          AND migration_id = '088_security_policy_activation'
          AND checksum_sha256 = '8cf9d78bbbb8156315b0b4dcd3ec2be0bd6c679dc65ee7c404447a1f7bdd5109'
          AND down_checksum_sha256 = '45597d926740c8ccadb059fbefcc97837df4d462f33e3123b37c5f5ec38b9132'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 089 requires the exact verified 088 release head'
            USING ERRCODE = 'P8900';
    END IF;
END;
$$;

CREATE FUNCTION dns_reconcile_operation_digest_089(operation jsonb)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(operation::text, 'UTF8'))
$$;

CREATE FUNCTION dns_reconcile_credential_digest_089(key_id text, ciphertext bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(key_id, 'UTF8') || decode('00', 'hex') || ciphertext)
$$;

CREATE FUNCTION dns_reconcile_site_config_digest_089(checked_site sites)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(jsonb_build_array(
        'cdnca:dns-reconcile:site-authority:v1',
        checked_site.id, checked_site.scope_id, checked_site.owner_user_id,
        checked_site.domain, checked_site.http_ports, checked_site.https_ports,
        checked_site.origins, checked_site.origin_hosts, checked_site.cname,
        checked_site.https_enabled, checked_site.enabled, checked_site.status,
        checked_site.sync_status, checked_site.is_default,
        checked_site.package_id, checked_site.package_name,
        checked_site.group_id, checked_site.group_name, checked_site.group_active,
        checked_site.region_id, checked_site.region_name,
        checked_site.node_group_id, checked_site.node_group_name,
        checked_site.lock_reason, checked_site.locked_by_user_id,
        checked_site.locked_at IS NOT NULL, checked_site.deleted_at IS NOT NULL
    )::text, 'UTF8'))
$$;

ALTER TABLE dns_reconcile_tasks
    ADD COLUMN provider_mutation_site_revision bigint CHECK (provider_mutation_site_revision > 0),
    ADD COLUMN provider_mutation_site_config_digest bytea
        CHECK (octet_length(provider_mutation_site_config_digest) = 32);

CREATE FUNCTION bind_dns_reconcile_task_site_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider_mutation_site_revision IS NOT NULL OR
       NEW.provider_mutation_site_config_digest IS NOT NULL THEN
        RAISE EXCEPTION 'DNS reconcile task site authority must be database bound'
            USING ERRCODE = 'P8902';
    END IF;
    SELECT site.revision,dns_reconcile_site_config_digest_089(site)
    INTO NEW.provider_mutation_site_revision,NEW.provider_mutation_site_config_digest
    FROM sites site
    WHERE site.scope_id=NEW.tenant_scope_id AND site.id=NEW.site_id AND site.deleted_at IS NULL
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'DNS reconcile task site authority is unavailable'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_tasks_bind_site_089
BEFORE INSERT ON dns_reconcile_tasks
FOR EACH ROW EXECUTE FUNCTION bind_dns_reconcile_task_site_089();

CREATE FUNCTION dns_reconcile_provider_config_digest_089(checked_zone dns_zones, checked_provider dns_providers)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(jsonb_build_array(
        checked_zone.id, checked_zone.scope_id, checked_zone.provider_id,
        checked_zone.name, checked_zone.status,
        checked_provider.id, checked_provider.scope_id, checked_provider.name,
        checked_provider.provider_type, checked_provider.status,
        checked_provider.credentials_configured
    )::text, 'UTF8'))
$$;

CREATE FUNCTION dns_reconcile_authority_digest_089(
    tenant_scope_id uuid,
    checked_site sites,
    checked_zone dns_zones,
    checked_provider dns_providers
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(
        convert_to(jsonb_build_array(
            tenant_scope_id,checked_site.id,checked_site.revision,
            checked_zone.revision,checked_provider.revision
        )::text, 'UTF8') ||
        dns_reconcile_site_config_digest_089(checked_site) ||
        dns_reconcile_provider_config_digest_089(checked_zone, checked_provider) ||
        dns_reconcile_credential_digest_089(
            checked_provider.credential_key_id, checked_provider.credential_ciphertext
        )
    )
$$;

CREATE TABLE dns_reconcile_provider_mutation_claims (
    tenant_id uuid NOT NULL,
    client_request_id text NOT NULL,
    job_id uuid NOT NULL,
    phase text NOT NULL,
    operation_ordinal integer NOT NULL,
    site_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL CHECK (isfinite(lease_expires_at)),
    recovery_not_before timestamptz CHECK (
        recovery_not_before IS NULL OR isfinite(recovery_not_before)
    ),
    state text NOT NULL CHECK (state IN ('claimed','uncertain','succeeded','not_applied','conflict')),
    expected_site_revision bigint NOT NULL CHECK (expected_site_revision > 0),
    expected_zone_revision bigint NOT NULL CHECK (expected_zone_revision > 0),
    expected_provider_revision bigint NOT NULL CHECK (expected_provider_revision > 0),
    site_config_digest bytea NOT NULL CHECK (octet_length(site_config_digest) = 32),
    operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
    authority_digest bytea NOT NULL CHECK (octet_length(authority_digest) = 32),
    provider_config_digest bytea NOT NULL CHECK (octet_length(provider_config_digest) = 32),
    credential_digest bytea NOT NULL CHECK (octet_length(credential_digest) = 32),
    provider_request_id text NOT NULL CHECK (
        octet_length(provider_request_id) BETWEEN 1 AND 256 AND
        provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    provider_record_id text CHECK (
        provider_record_id IS NULL OR (
            octet_length(provider_record_id) BETWEEN 1 AND 256 AND
            provider_record_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    final_zone_revision bigint CHECK (final_zone_revision IS NULL OR final_zone_revision > 0),
    claimed_at timestamptz NOT NULL CHECK (isfinite(claimed_at)),
    finalized_at timestamptz CHECK (finalized_at IS NULL OR isfinite(finalized_at)),
    PRIMARY KEY (tenant_id, client_request_id),
    UNIQUE (tenant_id, client_request_id, claim_id),
    FOREIGN KEY (tenant_id,job_id,phase,operation_ordinal)
        REFERENCES dns_reconcile_operations(tenant_id,job_id,phase,ordinal) ON DELETE RESTRICT,
    CHECK (lease_expires_at >= claimed_at),
    CHECK (
        (state = 'claimed' AND recovery_not_before IS NULL AND provider_record_id IS NULL AND
         final_zone_revision IS NULL AND finalized_at IS NULL) OR
        (state = 'uncertain' AND recovery_not_before IS NOT NULL AND provider_record_id IS NULL AND
         final_zone_revision IS NULL AND finalized_at IS NULL) OR
        (state = 'succeeded' AND provider_record_id IS NOT NULL AND
         final_zone_revision IS NOT NULL AND finalized_at IS NOT NULL) OR
        (state IN ('not_applied','conflict') AND provider_record_id IS NULL AND
         final_zone_revision IS NOT NULL AND finalized_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX dns_reconcile_provider_mutation_claims_active_zone_idx
    ON dns_reconcile_provider_mutation_claims (tenant_id, zone_id)
    WHERE state IN ('claimed','uncertain');

CREATE FUNCTION protect_dns_reconcile_provider_mutation_claim_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    valid_binding boolean;
    takeover boolean;
    renewal boolean;
    renewal_lease timestamptz;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider mutation claim facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dns_reconcile_operations operation
        JOIN dns_reconcile_tasks task
          ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
        JOIN access_scopes scope
          ON scope.id=task.tenant_scope_id AND scope.kind='tenant' AND scope.tenant_id=task.tenant_id
        JOIN sites site
          ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id AND site.deleted_at IS NULL
        JOIN dns_zones zone
          ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
        JOIN dns_providers provider
          ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
        WHERE operation.tenant_id=NEW.tenant_id
          AND operation.client_request_id=NEW.client_request_id
          AND operation.job_id=NEW.job_id
          AND operation.phase=NEW.phase
          AND operation.ordinal=NEW.operation_ordinal
          AND task.site_id=NEW.site_id
          AND task.zone_id=NEW.zone_id
          AND provider.id=NEW.provider_id
          AND task.provider_mutation_site_revision=NEW.expected_site_revision
          AND task.provider_mutation_site_config_digest=NEW.site_config_digest
          AND site.revision=NEW.expected_site_revision
          AND zone.revision=NEW.expected_zone_revision
          AND provider.revision=NEW.expected_provider_revision
          AND dns_reconcile_operation_digest_089(operation.operation)=NEW.operation_digest
          AND dns_reconcile_site_config_digest_089(site)=NEW.site_config_digest
          AND dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider)=NEW.authority_digest
          AND dns_reconcile_provider_config_digest_089(zone,provider)=NEW.provider_config_digest
          AND dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext)=NEW.credential_digest
    ) INTO valid_binding;
    IF NOT valid_binding THEN
        RAISE EXCEPTION 'invalid DNS provider mutation claim identity or digest'
            USING ERRCODE = 'P8902';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'claimed' OR NEW.claimed_at IS DISTINCT FROM statement_timestamp() OR
           NEW.lease_expires_at IS DISTINCT FROM statement_timestamp()+interval '2 minutes' OR
           NEW.recovery_not_before IS NOT NULL OR NEW.provider_record_id IS NOT NULL OR
           NEW.final_zone_revision IS NOT NULL OR NEW.finalized_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial DNS provider mutation claim'
                USING ERRCODE = 'P8902';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.tenant_id,NEW.client_request_id,NEW.job_id,NEW.phase,NEW.operation_ordinal,
           NEW.site_id,NEW.zone_id,NEW.provider_id,NEW.expected_zone_revision,
           NEW.expected_provider_revision,NEW.expected_site_revision,NEW.site_config_digest,
           NEW.operation_digest,NEW.authority_digest,NEW.provider_config_digest,NEW.credential_digest)
       IS DISTINCT FROM
       ROW(OLD.tenant_id,OLD.client_request_id,OLD.job_id,OLD.phase,OLD.operation_ordinal,
           OLD.site_id,OLD.zone_id,OLD.provider_id,OLD.expected_zone_revision,
           OLD.expected_provider_revision,OLD.expected_site_revision,OLD.site_config_digest,
           OLD.operation_digest,OLD.authority_digest,OLD.provider_config_digest,OLD.credential_digest) THEN
        RAISE EXCEPTION 'DNS provider mutation claim identity and digests are immutable'
            USING ERRCODE = 'P8902';
    END IF;

    IF NEW.provider_request_id IS DISTINCT FROM OLD.provider_request_id THEN
        RAISE EXCEPTION 'DNS provider mutation claim provider request id is immutable'
            USING ERRCODE = 'P8902';
    END IF;

    IF OLD.recovery_not_before IS NOT NULL AND
       NEW.recovery_not_before IS DISTINCT FROM OLD.recovery_not_before THEN
        RAISE EXCEPTION 'DNS provider mutation recovery time is immutable'
            USING ERRCODE = 'P8902';
    END IF;

    renewal_lease := GREATEST(OLD.lease_expires_at,statement_timestamp()+interval '17 minutes 30 seconds');
    renewal := OLD.state='claimed' AND NEW.state='claimed' AND NEW.claim_id=OLD.claim_id AND
        NEW.claimed_at=OLD.claimed_at AND OLD.lease_expires_at > statement_timestamp() AND
        NEW.lease_expires_at=renewal_lease AND NEW.provider_record_id IS NULL AND
        NEW.final_zone_revision IS NULL AND NEW.finalized_at IS NULL AND
        NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before;
    IF renewal THEN
        RETURN NEW;
    END IF;

    takeover := OLD.state IN ('claimed','uncertain','not_applied') AND
        NEW.state = CASE WHEN OLD.state='not_applied' THEN 'claimed' ELSE OLD.state END AND
        OLD.lease_expires_at <= statement_timestamp() AND NEW.claim_id <> OLD.claim_id AND
        NEW.lease_expires_at=statement_timestamp()+interval '2 minutes' AND
        NEW.claimed_at=statement_timestamp() AND
        ((OLD.state='not_applied' AND NEW.recovery_not_before IS NULL) OR
         (OLD.state<>'not_applied' AND NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before));
    IF takeover THEN
        IF NEW.state='claimed' AND (NEW.provider_record_id IS NOT NULL OR
           NEW.final_zone_revision IS NOT NULL OR NEW.finalized_at IS NOT NULL) THEN
            RAISE EXCEPTION 'invalid DNS provider mutation claim takeover'
                USING ERRCODE = 'P8902';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.claim_id <> OLD.claim_id OR NEW.claimed_at <> OLD.claimed_at OR
       NEW.lease_expires_at > OLD.lease_expires_at THEN
        RAISE EXCEPTION 'invalid DNS provider mutation claim token or lease transition'
            USING ERRCODE = 'P8902';
    END IF;
    IF OLD.state='claimed' AND NEW.state='uncertain' THEN
        IF NEW.recovery_not_before IS NOT NULL OR NEW.provider_request_id IS NULL OR
           NEW.provider_record_id IS NOT NULL OR NEW.final_zone_revision IS NOT NULL OR
           NEW.finalized_at IS NOT NULL THEN
            RAISE EXCEPTION 'DNS provider mutation recovery time must be database assigned'
                USING ERRCODE = 'P8902';
        END IF;
        NEW.recovery_not_before := clock_timestamp() + interval '2 minutes';
        RETURN NEW;
    END IF;
    IF OLD.state='uncertain' AND NEW.state='not_applied' AND
       NOT (OLD.recovery_not_before<=clock_timestamp()) THEN
        RAISE EXCEPTION 'DNS provider mutation recovery window has not elapsed'
            USING ERRCODE = 'P8902';
    END IF;
    IF OLD.state IN ('claimed','uncertain') AND NEW.state='succeeded' AND
       NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before AND
       NEW.provider_request_id IS NOT NULL AND NEW.provider_record_id IS NOT NULL AND
       NEW.final_zone_revision=NEW.expected_zone_revision+1 AND
       NEW.finalized_at>=statement_timestamp() AND NEW.finalized_at<=clock_timestamp() THEN
        RETURN NEW;
    END IF;
    IF OLD.state IN ('claimed','uncertain') AND NEW.state IN ('not_applied','conflict') AND
       NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before AND
       NEW.provider_record_id IS NULL AND NEW.final_zone_revision=NEW.expected_zone_revision AND
       NEW.finalized_at>=statement_timestamp() AND NEW.finalized_at<=clock_timestamp() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid DNS provider mutation claim transition or finalize'
        USING ERRCODE = 'P8902';
END;
$$;

CREATE TRIGGER dns_reconcile_provider_mutation_claims_protect_089
BEFORE TRUNCATE ON dns_reconcile_provider_mutation_claims
FOR EACH STATEMENT
EXECUTE FUNCTION protect_dns_reconcile_provider_mutation_claim_089();

CREATE TRIGGER dns_reconcile_provider_mutation_claims_validate_089
BEFORE INSERT OR UPDATE OR DELETE ON dns_reconcile_provider_mutation_claims
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_provider_mutation_claim_089();

CREATE FUNCTION validate_dns_reconcile_provider_mutation_success_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state='succeeded' AND (
       NEW.final_zone_revision<>NEW.expected_zone_revision+1 OR NOT EXISTS (
        SELECT 1
        FROM dns_reconcile_tasks task
        JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=NEW.zone_id
        WHERE task.tenant_id=NEW.tenant_id AND task.job_id=NEW.job_id
          AND zone.revision=NEW.final_zone_revision
    )) THEN
        RAISE EXCEPTION 'DNS provider mutation success requires the exact zone revision CAS'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER dns_reconcile_provider_mutation_claims_success_cas_089
AFTER INSERT OR UPDATE ON dns_reconcile_provider_mutation_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_provider_mutation_success_089();

CREATE FUNCTION block_dns_site_claimed_authority_mutation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (TG_OP='DELETE' OR to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD)) AND EXISTS (
        SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
        WHERE claim.site_id=OLD.id AND claim.state IN ('claimed','uncertain')
    ) THEN
        RAISE EXCEPTION 'active DNS provider mutation claim blocks site authority mutation'
            USING ERRCODE = 'P8903';
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sites_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_089();

CREATE FUNCTION block_dns_zone_claimed_authority_mutation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.provider_id,NEW.name,NEW.status,NEW.revision)
       IS DISTINCT FROM ROW(OLD.provider_id,OLD.name,OLD.status,OLD.revision) THEN
        IF EXISTS (
            SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
            WHERE claim.zone_id=OLD.id AND claim.state IN ('claimed','uncertain')
        ) THEN
            RAISE EXCEPTION 'active DNS provider mutation claim blocks zone authority mutation'
                USING ERRCODE = 'P8903';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_zones_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON dns_zones
FOR EACH ROW EXECUTE FUNCTION block_dns_zone_claimed_authority_mutation_089();

CREATE FUNCTION block_dns_provider_claimed_authority_mutation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.name,NEW.provider_type,NEW.status,NEW.revision,
                             NEW.credential_key_id,NEW.credential_ciphertext,NEW.credentials_configured)
       IS DISTINCT FROM ROW(OLD.name,OLD.provider_type,OLD.status,OLD.revision,
                            OLD.credential_key_id,OLD.credential_ciphertext,OLD.credentials_configured) THEN
        IF EXISTS (
            SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
            WHERE claim.provider_id=OLD.id AND claim.state IN ('claimed','uncertain')
        ) THEN
            RAISE EXCEPTION 'active DNS provider mutation claim blocks provider authority mutation'
                USING ERRCODE = 'P8903';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_providers_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON dns_providers
FOR EACH ROW EXECUTE FUNCTION block_dns_provider_claimed_authority_mutation_089();

CREATE TABLE dns_reconcile_provider_recovery_leases (
    tenant_id uuid NOT NULL,
    client_request_id text NOT NULL,
    claim_id uuid NOT NULL,
    job_id uuid NOT NULL,
    recovery_lease_id uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL CHECK (isfinite(lease_expires_at)),
    state text NOT NULL CHECK (state IN ('active','released','expired')),
    claimed_at timestamptz NOT NULL CHECK (isfinite(claimed_at)),
    released_at timestamptz CHECK (released_at IS NULL OR isfinite(released_at)),
    PRIMARY KEY (tenant_id,client_request_id,recovery_lease_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    CHECK (lease_expires_at>=claimed_at),
    CHECK ((state='active' AND released_at IS NULL) OR
           (state IN ('released','expired') AND released_at IS NOT NULL))
);

CREATE UNIQUE INDEX dns_reconcile_provider_recovery_leases_active_idx
    ON dns_reconcile_provider_recovery_leases(tenant_id,client_request_id)
    WHERE state='active';

CREATE FUNCTION protect_dns_reconcile_provider_recovery_lease_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider recovery lease facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.recovery_lease_id IS NULL OR NEW.state<>'active' OR NEW.released_at IS NOT NULL OR
           NOT EXISTS (
               SELECT 1
               FROM dns_reconcile_provider_mutation_claims claim
               LEFT JOIN dns_reconcile_provider_recovery_continuations continuation
                 ON continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id
               WHERE claim.tenant_id=NEW.tenant_id
                 AND claim.client_request_id=NEW.client_request_id
                 AND claim.claim_id=NEW.claim_id AND claim.job_id=NEW.job_id
                 AND continuation.tenant_id IS NULL
                 AND ((claim.state='uncertain' AND
                       claim.recovery_not_before<=clock_timestamp() AND
                       claim.lease_expires_at<=clock_timestamp()) OR
                      claim.state IN ('succeeded','not_applied','conflict'))
           ) THEN
            RAISE EXCEPTION 'invalid DNS provider recovery lease binding'
                USING ERRCODE = 'P8902';
        END IF;
        NEW.claimed_at:=statement_timestamp();
        NEW.lease_expires_at:=statement_timestamp()+interval '16 minutes';
        RETURN NEW;
    END IF;
    IF ROW(NEW.tenant_id,NEW.client_request_id,NEW.claim_id,NEW.job_id,
           NEW.recovery_lease_id,NEW.lease_expires_at,NEW.claimed_at)
       IS DISTINCT FROM
       ROW(OLD.tenant_id,OLD.client_request_id,OLD.claim_id,OLD.job_id,
           OLD.recovery_lease_id,OLD.lease_expires_at,OLD.claimed_at) OR
       OLD.state<>'active' OR NEW.state NOT IN ('released','expired') OR
       NEW.released_at IS NOT NULL OR
       (NEW.state='expired' AND OLD.lease_expires_at>clock_timestamp()) THEN
        RAISE EXCEPTION 'invalid DNS provider recovery lease transition'
            USING ERRCODE = 'P8902';
    END IF;
    NEW.released_at:=clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_provider_recovery_leases_protect_089
BEFORE TRUNCATE ON dns_reconcile_provider_recovery_leases
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_lease_089();
CREATE TRIGGER dns_reconcile_provider_recovery_leases_validate_089
BEFORE INSERT OR UPDATE OR DELETE ON dns_reconcile_provider_recovery_leases
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_lease_089();

CREATE TABLE dns_reconcile_provider_recovery_failures (
    tenant_id uuid NOT NULL,
    client_request_id text NOT NULL,
    claim_id uuid NOT NULL,
    job_id uuid NOT NULL,
    recovery_lease_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code IN (
        'provider_recovery_candidate_invalid',
        'provider_recovery_provider_unavailable',
        'provider_recovery_lookup_failed',
        'provider_recovery_requeue_failed'
    )),
    disposition text NOT NULL CHECK (disposition IN ('backoff','quarantined')),
    failure_count integer NOT NULL CHECK (failure_count > 0),
    retry_not_before timestamptz CHECK (
        retry_not_before IS NULL OR isfinite(retry_not_before)
    ),
    first_failed_at timestamptz NOT NULL CHECK (isfinite(first_failed_at)),
    last_failed_at timestamptz NOT NULL CHECK (isfinite(last_failed_at)),
    PRIMARY KEY (tenant_id,client_request_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    CHECK (
        (disposition='backoff' AND retry_not_before IS NOT NULL) OR
        (disposition='quarantined' AND retry_not_before IS NULL)
    )
);

CREATE FUNCTION protect_dns_reconcile_provider_recovery_failure_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    failed_at timestamptz;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider recovery failure facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;
    IF TG_OP='UPDATE' AND (
       ROW(NEW.tenant_id,NEW.client_request_id,NEW.job_id)
       IS DISTINCT FROM ROW(OLD.tenant_id,OLD.client_request_id,OLD.job_id) OR
       OLD.disposition='quarantined') THEN
        RAISE EXCEPTION 'DNS provider recovery failure identity or quarantine is immutable'
            USING ERRCODE = 'P8902';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
        WHERE claim.tenant_id=NEW.tenant_id AND claim.client_request_id=NEW.client_request_id
          AND claim.job_id=NEW.job_id
    ) OR NOT EXISTS (
        SELECT 1 FROM dns_reconcile_provider_recovery_leases recovery_lease
        WHERE recovery_lease.tenant_id=NEW.tenant_id
          AND recovery_lease.client_request_id=NEW.client_request_id
          AND recovery_lease.claim_id=NEW.claim_id
          AND recovery_lease.job_id=NEW.job_id
          AND recovery_lease.recovery_lease_id=NEW.recovery_lease_id
          AND recovery_lease.state='active'
    ) THEN
        RAISE EXCEPTION 'invalid DNS provider recovery failure binding'
            USING ERRCODE = 'P8902';
    END IF;
    failed_at := clock_timestamp();
    IF TG_OP='INSERT' THEN
        NEW.failure_count := 1;
        NEW.first_failed_at := failed_at;
    ELSE
        NEW.failure_count := OLD.failure_count+1;
        NEW.first_failed_at := OLD.first_failed_at;
    END IF;
    NEW.last_failed_at := failed_at;
    NEW.retry_not_before := CASE WHEN NEW.disposition='backoff'
        THEN failed_at + make_interval(secs => LEAST(60,5*NEW.failure_count))
        ELSE NULL END;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_provider_recovery_failures_protect_089
BEFORE TRUNCATE ON dns_reconcile_provider_recovery_failures
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_failure_089();
CREATE TRIGGER dns_reconcile_provider_recovery_failures_validate_089
BEFORE INSERT OR UPDATE OR DELETE ON dns_reconcile_provider_recovery_failures
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_failure_089();

CREATE TABLE dns_reconcile_provider_recovery_continuations (
    tenant_id uuid NOT NULL,
    client_request_id text NOT NULL,
    claim_id uuid NOT NULL,
    job_id uuid NOT NULL,
    continuation_attempt integer NOT NULL CHECK (continuation_attempt > 1 AND continuation_attempt <= 1001),
    previous_item_attempt integer NOT NULL CHECK (previous_item_attempt > 0),
    previous_item_sequence bigint NOT NULL CHECK (previous_item_sequence > 0),
    result_attempts integer NOT NULL CHECK (result_attempts > 0),
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    recovery_event_sequence bigint NOT NULL CHECK (recovery_event_sequence > 1),
    recovery_result_digest bytea NOT NULL CHECK (octet_length(recovery_result_digest) = 32),
    granted_at timestamptz NOT NULL CHECK (isfinite(granted_at)),
    consumed_at timestamptz CHECK (consumed_at IS NULL OR isfinite(consumed_at)),
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_id,client_request_id,claim_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT
);

CREATE FUNCTION protect_dns_reconcile_provider_recovery_continuation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    valid_grant boolean;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider recovery continuation facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.tenant_id,NEW.client_request_id,NEW.claim_id,NEW.job_id,
               NEW.continuation_attempt,NEW.previous_item_attempt,NEW.previous_item_sequence,
               NEW.result_attempts,NEW.event_sequence,NEW.recovery_event_sequence,
               NEW.recovery_result_digest,NEW.granted_at)
           IS DISTINCT FROM
           ROW(OLD.tenant_id,OLD.client_request_id,OLD.claim_id,OLD.job_id,
               OLD.continuation_attempt,OLD.previous_item_attempt,OLD.previous_item_sequence,
               OLD.result_attempts,OLD.event_sequence,OLD.recovery_event_sequence,
               OLD.recovery_result_digest,OLD.granted_at) OR
           OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
            RAISE EXCEPTION 'DNS provider recovery continuation fact is immutable'
                USING ERRCODE = 'P8902';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM background_jobs job
            JOIN background_job_items item
              ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id='reconcile'
            WHERE job.tenant_id=OLD.tenant_id AND job.id=OLD.job_id
              AND job.kind='dns_reconcile' AND job.state='queued'
              AND job.attempt=OLD.continuation_attempt-1
              AND job.max_attempts=OLD.continuation_attempt
              AND job.claimable_at=OLD.granted_at AND job.updated_at=OLD.granted_at
              AND item.state='pending' AND item.attempt=OLD.previous_item_attempt
              AND item.sequence=OLD.previous_item_sequence
        ) THEN
            RAISE EXCEPTION 'DNS provider recovery continuation was not atomically applied'
                USING ERRCODE = 'P8902';
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM dns_reconcile_provider_mutation_claims claim
            JOIN dns_reconcile_operations operation
              ON operation.tenant_id=claim.tenant_id AND operation.job_id=claim.job_id
             AND operation.phase=claim.phase AND operation.ordinal=claim.operation_ordinal
            JOIN dns_reconcile_task_events previous_event
              ON previous_event.tenant_id=claim.tenant_id AND previous_event.job_id=claim.job_id
             AND previous_event.event_sequence=OLD.event_sequence
            JOIN dns_reconcile_task_events recovery_event
              ON recovery_event.tenant_id=claim.tenant_id AND recovery_event.job_id=claim.job_id
             AND recovery_event.event_sequence=OLD.recovery_event_sequence
            WHERE claim.tenant_id=OLD.tenant_id AND claim.client_request_id=OLD.client_request_id
              AND claim.claim_id=OLD.claim_id AND claim.job_id=OLD.job_id AND claim.phase='apply'
              AND OLD.recovery_event_sequence=OLD.event_sequence+1
              AND recovery_event.source='control' AND recovery_event.status='applying'
              AND COALESCE(recovery_event.error_class,'')='' AND recovery_event.error_code IS NULL
              AND sha256(convert_to(recovery_event.result_snapshot::text,'UTF8'))=OLD.recovery_result_digest
              AND recovery_event.result_snapshot->>'TenantID'=claim.tenant_id::text
              AND recovery_event.result_snapshot->>'SiteID'=claim.site_id::text
              AND recovery_event.result_snapshot->>'ZoneID'=claim.zone_id::text
              AND recovery_event.result_snapshot->>'Status'='applying'
              AND recovery_event.result_snapshot->>'ErrorClass'=''
              AND recovery_event.result_snapshot->>'ErrorCode'=''
              AND recovery_event.result_snapshot->'CompensationPlan'='[]'::jsonb
              AND (recovery_event.result_snapshot-'UpdatedAt'-'Status'-'ErrorClass'-'ErrorCode'-'CompensationPlan'-'Operations')=
                  (previous_event.result_snapshot-'UpdatedAt'-'Status'-'ErrorClass'-'ErrorCode'-'CompensationPlan'-'Operations')
              AND ((recovery_event.result_snapshot->'Operations')-(claim.operation_ordinal-1))=
                  ((previous_event.result_snapshot->'Operations')-(claim.operation_ordinal-1))
              AND ((recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1))-
                   'Status'-'ErrorClass'-'ErrorCode')=
                  ((previous_event.result_snapshot->'Operations'->(claim.operation_ordinal-1))-
                   'Status'-'ErrorClass'-'ErrorCode')
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ClientRequestID'=
                  claim.client_request_id
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->'Operation'=
                  operation.operation
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'Status'='planned'
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ErrorClass'=''
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ErrorCode'=''
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->'Attempts'=
                  to_jsonb(OLD.result_attempts)
        ) THEN
            RAISE EXCEPTION 'DNS provider recovery continuation event is invalid'
                USING ERRCODE = 'P8902';
        END IF;
        NEW.consumed_at := clock_timestamp();
        RETURN NEW;
    END IF;
	IF EXISTS (
		SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
		WHERE continuation.tenant_id=NEW.tenant_id AND
		      (continuation.job_id=NEW.job_id OR
		       (continuation.client_request_id=NEW.client_request_id AND continuation.claim_id=NEW.claim_id))
	) THEN
		RAISE EXCEPTION 'DNS provider recovery continuation grant already exists'
			USING ERRCODE = 'P8902';
	END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dns_reconcile_provider_mutation_claims claim
        JOIN background_jobs job
          ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
        JOIN background_job_items item
          ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id='reconcile'
        JOIN dns_zones zone ON zone.id=claim.zone_id
        JOIN LATERAL (
            SELECT event.event_sequence,event.error_code,event.result_snapshot
            FROM dns_reconcile_task_events event
            WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
            ORDER BY event.event_sequence DESC LIMIT 1
        ) latest ON true
        WHERE claim.tenant_id=NEW.tenant_id AND claim.client_request_id=NEW.client_request_id
          AND claim.claim_id=NEW.claim_id AND claim.job_id=NEW.job_id AND claim.phase='apply'
          AND claim.state IN ('succeeded','not_applied','conflict')
          AND zone.revision=claim.final_zone_revision
          AND job.kind='dns_reconcile' AND job.state IN ('failed','partial_failed')
          AND job.attempt=job.max_attempts AND job.attempt>=1
          AND job.cancel_requested_at IS NULL
          AND NEW.continuation_attempt=job.attempt+1 AND NEW.continuation_attempt<=1001
          AND NEW.recovery_event_sequence=NEW.event_sequence+1
          AND item.state='failed' AND item.attempt=NEW.previous_item_attempt
          AND item.sequence=NEW.previous_item_sequence
          AND latest.event_sequence=NEW.event_sequence
          AND latest.error_code IN ('provider_recovery_pending','provider_recovery_persistence_failed')
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'ClientRequestID'=claim.client_request_id
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'Status'='transient_failed'
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'ErrorCode'=latest.error_code
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) -> 'Attempts'=to_jsonb(NEW.result_attempts)
    ) INTO valid_grant;
    IF NOT valid_grant THEN
        RAISE EXCEPTION 'invalid DNS provider recovery continuation grant'
            USING ERRCODE = 'P8902';
    END IF;
    NEW.granted_at := clock_timestamp();
    NEW.consumed_at := NULL;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_provider_recovery_continuations_protect_089
BEFORE TRUNCATE ON dns_reconcile_provider_recovery_continuations
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_continuation_089();
CREATE TRIGGER dns_reconcile_provider_recovery_continuations_validate_089
BEFORE INSERT OR UPDATE OR DELETE ON dns_reconcile_provider_recovery_continuations
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_provider_recovery_continuation_089();

CREATE FUNCTION validate_dns_reconcile_provider_recovery_continuation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM dns_reconcile_provider_recovery_continuations continuation
    JOIN dns_reconcile_provider_mutation_claims claim
      ON claim.tenant_id=continuation.tenant_id
     AND claim.client_request_id=continuation.client_request_id
     AND claim.claim_id=continuation.claim_id AND claim.job_id=continuation.job_id
    JOIN dns_reconcile_tasks task
      ON task.tenant_id=claim.tenant_id AND task.job_id=claim.job_id
    JOIN dns_zones zone
      ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id AND zone.id=claim.zone_id
    WHERE continuation.tenant_id=NEW.tenant_id AND continuation.job_id=NEW.job_id
      AND continuation.client_request_id=NEW.client_request_id
      AND continuation.claim_id=NEW.claim_id
      AND claim.state IN ('succeeded','not_applied','conflict')
      AND claim.final_zone_revision IS NOT NULL
      AND zone.revision=claim.final_zone_revision
    FOR UPDATE OF zone;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'DNS provider recovery continuation zone revision changed before commit'
            USING ERRCODE = 'P8902';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
        WHERE continuation.tenant_id=NEW.tenant_id AND continuation.job_id=NEW.job_id
          AND continuation.consumed_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1
        FROM dns_reconcile_provider_recovery_continuations continuation
        JOIN dns_reconcile_task_events event
          ON event.tenant_id=continuation.tenant_id AND event.job_id=continuation.job_id
         AND event.event_sequence=continuation.recovery_event_sequence
        WHERE continuation.tenant_id=NEW.tenant_id AND continuation.job_id=NEW.job_id
          AND continuation.client_request_id=NEW.client_request_id
          AND continuation.claim_id=NEW.claim_id
          AND continuation.recovery_event_sequence=continuation.event_sequence+1
          AND sha256(convert_to(event.result_snapshot::text,'UTF8'))=continuation.recovery_result_digest
    ) THEN
        RAISE EXCEPTION 'DNS provider recovery continuation grant or event is incomplete'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER dns_reconcile_provider_recovery_continuations_consumed_089
AFTER INSERT ON dns_reconcile_provider_recovery_continuations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_provider_recovery_continuation_089();

CREATE FUNCTION dns_reconcile_background_job_recovery_retry_089(
    previous_job background_jobs,
    recovery_job background_jobs
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT previous_job.kind='dns_reconcile' AND
        previous_job.state IN ('failed','partial_failed') AND
        previous_job.attempt=previous_job.max_attempts AND previous_job.attempt>=1 AND
        previous_job.cancel_requested_at IS NULL AND recovery_job.state='queued' AND
        recovery_job.attempt=previous_job.attempt AND
        recovery_job.max_attempts=previous_job.max_attempts+1 AND
        recovery_job.lease_id IS NULL AND recovery_job.lease_owner IS NULL AND
        recovery_job.lease_expires_at IS NULL AND recovery_job.claimable_at IS NOT NULL AND
        recovery_job.completed_count=previous_job.succeeded_count AND
        recovery_job.succeeded_count=previous_job.succeeded_count AND
        recovery_job.failed_count=0 AND recovery_job.cancelled_count=0 AND
        recovery_job.last_error_code IS NULL AND recovery_job.completed_at IS NULL AND
        ROW(recovery_job.id,recovery_job.tenant_id,recovery_job.kind,recovery_job.subject,
            recovery_job.idempotency_key,recovery_job.request_digest,recovery_job.request_id,
            recovery_job.trace_id,recovery_job.cancel_requested_at,recovery_job.total_count,
            recovery_job.created_at,recovery_job.started_at)
        IS NOT DISTINCT FROM
        ROW(previous_job.id,previous_job.tenant_id,previous_job.kind,previous_job.subject,
            previous_job.idempotency_key,previous_job.request_digest,previous_job.request_id,
            previous_job.trace_id,previous_job.cancel_requested_at,previous_job.total_count,
            previous_job.created_at,previous_job.started_at) AND EXISTS (
            SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
            WHERE continuation.tenant_id=previous_job.tenant_id
              AND continuation.job_id=previous_job.id AND continuation.consumed_at IS NULL
              AND continuation.continuation_attempt=recovery_job.max_attempts
              AND continuation.granted_at=recovery_job.claimable_at
              AND continuation.granted_at=recovery_job.updated_at
              AND continuation.granted_at<=clock_timestamp()
        )
$$;

CREATE FUNCTION dns_reconcile_background_job_item_recovery_retry_089(
    previous_item background_job_items,
    recovery_item background_job_items
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT previous_item.state='failed' AND recovery_item.state='pending' AND
        recovery_item.attempt=previous_item.attempt AND
        recovery_item.sequence=previous_item.sequence AND
        recovery_item.error_code IS NULL AND recovery_item.completed_at IS NULL AND
        ROW(recovery_item.tenant_id,recovery_item.job_id,recovery_item.ordinal,
            recovery_item.item_id,recovery_item.node_id)
        IS NOT DISTINCT FROM
        ROW(previous_item.tenant_id,previous_item.job_id,previous_item.ordinal,
            previous_item.item_id,previous_item.node_id) AND EXISTS (
            SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
            JOIN background_jobs job
              ON job.tenant_id=continuation.tenant_id AND job.id=continuation.job_id
            WHERE continuation.tenant_id=previous_item.tenant_id
              AND continuation.job_id=previous_item.job_id AND continuation.consumed_at IS NULL
              AND continuation.previous_item_attempt=previous_item.attempt
              AND continuation.previous_item_sequence=previous_item.sequence
              AND job.state='queued' AND job.max_attempts=continuation.continuation_attempt
        )
$$;

CREATE FUNCTION validate_dns_reconcile_background_job_recovery_retry_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (EXISTS (
        SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
        WHERE continuation.tenant_id=OLD.tenant_id AND continuation.job_id=OLD.id
          AND continuation.consumed_at IS NULL
    ) OR (OLD.kind='dns_reconcile' AND OLD.state IN ('failed','partial_failed') AND
          NEW.state='queued' AND NEW.max_attempts=OLD.max_attempts+1)) AND
       NOT dns_reconcile_background_job_recovery_retry_089(OLD,NEW) THEN
        RAISE EXCEPTION 'invalid DNS provider recovery job continuation'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_background_job_item_recovery_retry_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
        WHERE continuation.tenant_id=OLD.tenant_id AND continuation.job_id=OLD.job_id
          AND continuation.consumed_at IS NULL
    ) AND NOT dns_reconcile_background_job_item_recovery_retry_089(OLD,NEW) THEN
        RAISE EXCEPTION 'invalid DNS provider recovery item continuation'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NEW;
END;
$$;

LOCK TABLE background_jobs,background_job_items IN ACCESS EXCLUSIVE MODE;
DROP TRIGGER background_jobs_protected ON background_jobs;
CREATE TRIGGER a_dns_reconcile_background_jobs_recovery_validated_089
BEFORE UPDATE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_background_job_recovery_retry_089();
CREATE TRIGGER background_jobs_protected
BEFORE UPDATE ON background_jobs
FOR EACH ROW
WHEN (NOT dns_reconcile_background_job_recovery_retry_089(OLD,NEW))
EXECUTE FUNCTION protect_background_job();

DROP TRIGGER background_job_items_protected ON background_job_items;
CREATE TRIGGER a_dns_reconcile_background_job_items_recovery_validated_089
BEFORE UPDATE ON background_job_items
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_background_job_item_recovery_retry_089();
CREATE TRIGGER background_job_items_protected
BEFORE UPDATE ON background_job_items
FOR EACH ROW
WHEN (NOT dns_reconcile_background_job_item_recovery_retry_089(OLD,NEW))
EXECUTE FUNCTION protect_background_job_item();

ALTER TABLE background_job_items DROP CONSTRAINT background_job_items_check;
ALTER TABLE background_job_items ADD CONSTRAINT background_job_items_check CHECK (
    (state='pending' AND error_code IS NULL AND completed_at IS NULL) OR
    (state='succeeded' AND attempt>0 AND sequence>0 AND error_code IS NULL AND completed_at IS NOT NULL) OR
    (state='failed' AND attempt>0 AND error_code IS NOT NULL AND completed_at IS NOT NULL) OR
    (state='cancelled' AND error_code='cancelled' AND completed_at IS NOT NULL)
);
