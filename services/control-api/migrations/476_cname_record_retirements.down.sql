LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE cname_allocations, cname_hostname_claims, sites IN SHARE ROW EXCLUSIVE MODE;

DO $migration_476_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 476 OR
       (SELECT max(version) FROM schema_migrations) <> 476 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=476 AND
        migration_id='476_cname_record_retirements' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 476 down requires the exact verified migration head' USING ERRCODE='P4761';
    END IF;
    -- 113's rotation rule cannot be restored over a regeneration it refused,
    -- and pending retirements are owners still on the provider.
    IF EXISTS (SELECT 1 FROM cname_record_retirements WHERE state='pending') OR EXISTS (
        SELECT 1 FROM cname_hostname_claims current_claim
        JOIN cname_hostname_claims prior_claim ON prior_claim.allocation_id=current_claim.allocation_id
         AND prior_claim.generation<current_claim.generation AND NOT prior_claim.explicit_hostname
         AND prior_claim.hmac_key_id IS NOT DISTINCT FROM current_claim.hmac_key_id
        WHERE NOT current_claim.explicit_hostname
    ) THEN
        RAISE EXCEPTION 'migration 476 down refuses pending CNAME retirements or same-key regenerations'
            USING ERRCODE='P4761';
    END IF;
END;
$migration_476_down$;

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
    ELSE
        IF current_claim.generation IS DISTINCT FROM NEW.generation THEN
            RAISE EXCEPTION 'generated CNAME claim must be new for the allocation generation'
                USING ERRCODE='P1131';
        END IF;
        IF EXISTS (
            SELECT 1 FROM cname_hostname_claims AS prior_claim
            WHERE prior_claim.allocation_id=NEW.id
              AND prior_claim.generation<NEW.generation
              AND NOT prior_claim.explicit_hostname
              AND prior_claim.hmac_key_id IS NOT DISTINCT FROM current_claim.hmac_key_id
        ) THEN
            RAISE EXCEPTION 'generated CNAME regeneration must rotate its HMAC key'
                USING ERRCODE='P1131';
        END IF;
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

DROP FUNCTION cname_claim_released_476(uuid);
DROP TABLE cname_record_retirements;
DROP FUNCTION validate_cname_record_retirement_476();
