LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE cname_allocations, cname_hostname_claims, sites IN SHARE ROW EXCLUSIVE MODE;

DO $migration_476_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 475 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 475 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=474 AND
        migration_id='474_site_claim_guard_runtime_observation' AND
        checksum_sha256='2ea02118cbf180d14424e57b201a8c76dc16c5908bc8f498874056cda402fb5c' AND
        down_checksum_sha256='a9c1f44b863a6358876eca432fb44c8f4fd2f5cefea559124cd4a7b8b4c13058' AND
        integrity_state='verified'
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('cname_record_retirements') IS NOT NULL OR
       to_regprocedure('assert_cname_allocation_consistency_113()') IS NULL THEN
        RAISE EXCEPTION 'migration 476 requires the exact verified release head with 474 and 113''s CNAME authority'
            USING ERRCODE='P4760';
    END IF;
END;
$migration_476_up$;

-- r136 n12b: a CNAME owner written to the DNS provider stayed there after
-- the site was deleted or the allocation moved to a new generation (claims
-- are append-only and 清除CDN无关解析 treated every claimed hostname as in
-- use). A retirement is registered in the same transaction as the delete or
-- the generation advance; the CNAME worker deletes the records the system
-- wrote under the owner once the claim is released (below) and records the
-- outcome. Identity is immutable; only the cleanup progress changes.
CREATE TABLE cname_record_retirements (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    claim_id uuid NOT NULL UNIQUE,
    site_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    owner_name text NOT NULL CHECK (
        owner_name=lower(btrim(owner_name)) AND char_length(owner_name) BETWEEN 1 AND 253
    ),
    reason text NOT NULL CHECK (reason IN ('site_deleted','generation_rotated')),
    state text NOT NULL CHECK (state IN ('pending','cleaned','failed')),
    -- Not cleaned before this: a rotated owner keeps answering for a grace
    -- period so customers can repoint their own CNAME to the new hostname.
    eligible_at timestamptz NOT NULL CHECK (isfinite(eligible_at)),
    attempts integer NOT NULL CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    last_error_code text CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    deleted_records integer NOT NULL DEFAULT 0 CHECK (deleted_records >= 0),
    kept_records integer NOT NULL DEFAULT 0 CHECK (kept_records >= 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    completed_at timestamptz CHECK (completed_at IS NULL OR (isfinite(completed_at) AND completed_at >= created_at)),
    FOREIGN KEY (tenant_scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,allocation_id)
        REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (claim_id,allocation_id)
        REFERENCES cname_hostname_claims(id,allocation_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    CHECK (eligible_at >= created_at AND next_attempt_at >= eligible_at),
    CHECK ((state='pending') = (completed_at IS NULL)),
    CHECK (state<>'failed' OR last_error_code IS NOT NULL)
);

CREATE INDEX cname_record_retirements_pending_476_idx
    ON cname_record_retirements (next_attempt_at,id) WHERE state='pending';

CREATE FUNCTION validate_cname_record_retirement_476()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    claim_row cname_hostname_claims%ROWTYPE;
BEGIN
    IF TG_OP<>'INSERT' AND TG_OP<>'UPDATE' THEN
        RAISE EXCEPTION 'CNAME record retirements are durable facts' USING ERRCODE='P4762';
    END IF;
    IF TG_OP='INSERT' THEN
        SELECT * INTO claim_row FROM cname_hostname_claims
        WHERE id=NEW.claim_id AND allocation_id=NEW.allocation_id;
        IF claim_row.id IS NULL OR claim_row.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR
           claim_row.provider_id IS DISTINCT FROM NEW.provider_id OR
           claim_row.zone_id IS DISTINCT FROM NEW.zone_id OR
           lower(claim_row.hostname) IS DISTINCT FROM NEW.owner_name OR
           NEW.state<>'pending' OR NEW.attempts<>0 OR NEW.last_error_code IS NOT NULL OR
           NEW.deleted_records<>0 OR NEW.kept_records<>0 OR
           NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'CNAME record retirement must start pending for its exact claim'
                USING ERRCODE='P4762';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.tenant_id,NEW.tenant_scope_id,NEW.allocation_id,NEW.claim_id,NEW.site_id,
           NEW.provider_id,NEW.zone_id,NEW.owner_name,NEW.reason,NEW.eligible_at,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.tenant_scope_id,OLD.allocation_id,OLD.claim_id,OLD.site_id,
           OLD.provider_id,OLD.zone_id,OLD.owner_name,OLD.reason,OLD.eligible_at,OLD.created_at) OR
       OLD.state<>'pending' OR NEW.attempts < OLD.attempts OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'CNAME record retirement identity is immutable and only pending progresses'
            USING ERRCODE='P4762';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cname_record_retirements_validate_476
BEFORE INSERT OR UPDATE OR DELETE ON cname_record_retirements
FOR EACH ROW EXECUTE FUNCTION validate_cname_record_retirement_476();
CREATE TRIGGER cname_record_retirements_no_truncate_476
BEFORE TRUNCATE ON cname_record_retirements
FOR EACH STATEMENT EXECUTE FUNCTION validate_cname_record_retirement_476();

-- A retired claim is released (the worker may clean its owner, and
-- 清除CDN无关解析 no longer treats it as in use) after eligible_at once no
-- live site serves it: no binding of an undeleted site has its allocation as
-- current (current or LKG claim) or as LKG allocation (LKG claim). A rotated
-- generation that was done stays LKG, and so on the provider, until the next
-- generation is done; a deleted site's binding no longer counts.
CREATE FUNCTION cname_claim_released_476(retired_claim_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM cname_record_retirements retirement
        WHERE retirement.claim_id=retired_claim_id AND retirement.eligible_at<=clock_timestamp()
          AND NOT EXISTS (
            SELECT 1 FROM cname_site_bindings binding
            JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
             AND site.deleted_at IS NULL
            JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
             AND allocation.id=retirement.allocation_id
            WHERE binding.tenant_scope_id=retirement.tenant_scope_id AND (
                (binding.current_allocation_id=allocation.id AND
                 retirement.claim_id IN (allocation.current_claim_id,allocation.lkg_claim_id)) OR
                (binding.lkg_allocation_id=allocation.id AND retirement.claim_id=allocation.lkg_claim_id))))
$$;

-- Owners already leaked before this migration: every claim no live site
-- serves, except a package allocation's current/LKG claim (the
-- subscription's next site binds it again).
INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,site_id,
    provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,
    COALESCE(allocation.site_owner_id,bound.site_id),claim.provider_id,claim.zone_id,lower(claim.hostname),
    retired.reason,retired.eligible_at,'pending',0,retired.eligible_at,clock_timestamp(),clock_timestamp()
FROM cname_allocations allocation
JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id
LEFT JOIN LATERAL (SELECT binding.site_id FROM cname_site_bindings binding
    WHERE binding.tenant_scope_id=allocation.tenant_scope_id
      AND allocation.id IN (binding.current_allocation_id,binding.lkg_allocation_id)
    ORDER BY binding.site_id LIMIT 1) bound ON true
LEFT JOIN sites site ON site.scope_id=allocation.tenant_scope_id AND site.id=allocation.site_owner_id
CROSS JOIN LATERAL (SELECT
    CASE WHEN site.deleted_at IS NOT NULL THEN 'site_deleted' ELSE 'generation_rotated' END AS reason,
    CASE WHEN site.deleted_at IS NOT NULL THEN clock_timestamp()
         ELSE GREATEST(clock_timestamp(),allocation.updated_at+interval '24 hours') END AS eligible_at) retired
WHERE COALESCE(allocation.site_owner_id,bound.site_id) IS NOT NULL
  AND NOT (allocation.mode='package' AND claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id))
  AND NOT EXISTS (
    SELECT 1 FROM cname_site_bindings binding
    JOIN sites live ON live.scope_id=binding.tenant_scope_id AND live.id=binding.site_id AND live.deleted_at IS NULL
    WHERE binding.tenant_scope_id=allocation.tenant_scope_id AND (
        (binding.current_allocation_id=allocation.id AND
         claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id)) OR
        (binding.lkg_allocation_id=allocation.id AND claim.id=allocation.lkg_claim_id)));

-- P1131 on 「重新生成」 after a failed allocation: 113 required a generated
-- claim of a new generation to use another HMAC key than every earlier one,
-- but the runtime has exactly one key (CNAME_ALLOCATION_HMAC_KEY_ID) and no
-- rotation, so every tenant regeneration was refused and the intent retried
-- forever. The generation is part of the label HMAC input
-- (cnameallocation/label.go), the allocator skips any claimed name, and
-- cname_hostname_claims_hostname_113_uidx keeps names globally unique: a new
-- generation already gets a new name with the same key. The rest of 113's
-- consistency check is unchanged.
CREATE OR REPLACE FUNCTION assert_cname_allocation_consistency_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_claim cname_hostname_claims%ROWTYPE;
    lkg_claim cname_hostname_claims%ROWTYPE;
    job_row background_jobs%ROWTYPE;
BEGIN
    SELECT * INTO current_claim FROM cname_hostname_claims
    WHERE id=NEW.current_claim_id AND allocation_id=NEW.id;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF current_claim.id IS NULL OR current_claim.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR
       job_row.id IS NULL OR job_row.kind IS DISTINCT FROM 'dns.cname.allocation' THEN
        RAISE EXCEPTION 'CNAME allocation claim or job identity is invalid' USING ERRCODE='P1131';
    END IF;
    IF current_claim.explicit_hostname THEN
        IF current_claim.generation > NEW.generation THEN
            RAISE EXCEPTION 'explicit CNAME claim generation is ahead of its allocation'
                USING ERRCODE='P1131';
        END IF;
    ELSIF current_claim.generation IS DISTINCT FROM NEW.generation THEN
        RAISE EXCEPTION 'generated CNAME claim must be new for the allocation generation'
            USING ERRCODE='P1131';
    END IF;
    IF NEW.lkg_claim_id IS NOT NULL THEN
        SELECT * INTO lkg_claim FROM cname_hostname_claims
        WHERE id=NEW.lkg_claim_id AND allocation_id=NEW.id;
        IF lkg_claim.id IS NULL OR lkg_claim.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR
           lkg_claim.generation > NEW.generation THEN
            RAISE EXCEPTION 'CNAME allocation LKG claim is invalid' USING ERRCODE='P1131';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

GRANT SELECT, INSERT, UPDATE ON cname_record_retirements TO cdnca_control_app, cdnca_control_runtime;
