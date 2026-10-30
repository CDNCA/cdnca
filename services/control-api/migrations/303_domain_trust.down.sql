LOCK TABLE schema_migrations, permissions, roles, role_permissions, sites, site_domain_facts,
    site_domain_active, domain_ownerships, domain_claim_suspensions, platform_domain_blocklist,
    domain_trust_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_303_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 303 OR
       (SELECT max(version) FROM schema_migrations) <> 303 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=303 AND
        migration_id='303_domain_trust' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 303 down requires the exact verified migration head' USING ERRCODE='P3031';
    END IF;
    -- Ownership proofs, suspensions and blocklist entries must not vanish
    -- silently; the operator removes them first.
    IF EXISTS (SELECT 1 FROM domain_ownerships) OR EXISTS (SELECT 1 FROM domain_claim_suspensions) OR
       EXISTS (SELECT 1 FROM platform_domain_blocklist) THEN
        RAISE EXCEPTION 'migration 303 rollback would discard domain ownership, claim or blocklist records'
            USING ERRCODE='P3031';
    END IF;
END;
$migration_303_down$;

DROP TRIGGER sites_domain_claim_suspended_299 ON sites;
DROP TRIGGER site_domain_facts_project_299 ON site_domain_facts;

-- Restore the 148 function body exactly.
CREATE OR REPLACE FUNCTION guard_site_domain_fact_148()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    candidate_base text := regexp_replace(NEW.canonical_domain,'^\*\.','');
BEGIN
    PERFORM pg_advisory_xact_lock(148, 1);
    IF NEW.action = 'activate' AND EXISTS (
        WITH latest AS (
            SELECT DISTINCT ON (canonical_domain) scope_id,site_id,canonical_domain,action
            FROM site_domain_facts
            ORDER BY canonical_domain,global_sequence DESC
        )
        SELECT 1 FROM latest
        WHERE action='activate' AND (scope_id,site_id) <> (NEW.scope_id,NEW.site_id) AND (
            canonical_domain = NEW.canonical_domain OR
            (canonical_domain LIKE '*.%' AND NEW.canonical_domain NOT LIKE '*.%' AND
             NEW.canonical_domain LIKE '%.' || substring(canonical_domain FROM 3) AND
             array_length(string_to_array(NEW.canonical_domain,'.'),1) =
                array_length(string_to_array(substring(canonical_domain FROM 3),'.'),1) + 1) OR
            (NEW.canonical_domain LIKE '*.%' AND canonical_domain NOT LIKE '*.%' AND
             canonical_domain LIKE '%.' || candidate_base AND
             array_length(string_to_array(canonical_domain,'.'),1) =
                array_length(string_to_array(candidate_base,'.'),1) + 1)
        )
    ) THEN
        RAISE EXCEPTION 'site domain wildcard overlap'
            USING ERRCODE = '23505', CONSTRAINT = 'site_domain_facts_overlap_148';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION guard_site_claim_suspension_299();
DROP FUNCTION project_site_domain_fact_299();
DROP TABLE domain_trust_write_requests;
DROP TABLE platform_domain_blocklist;
DROP TABLE domain_claim_suspensions;
DROP TABLE domain_ownerships;
DROP TABLE site_domain_active;
DROP FUNCTION lock_site_domains_299(text[]);
DROP FUNCTION site_domain_family_299(text);

-- notification_templates rows are immutable (029) and stay; they are unused
-- without the domain trust tables.
DELETE FROM role_permissions WHERE permission_name = 'domains.security.manage';
DELETE FROM permissions WHERE name = 'domains.security.manage';
