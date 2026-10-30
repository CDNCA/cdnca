LOCK TABLE schema_migrations, permissions, roles, role_permissions, access_scopes, sites,
    site_domain_facts, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_303_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 302 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 302 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=302 AND
        migration_id='302_tickets' AND
        checksum_sha256='dacca1529d3d10f48f75125ec29d82ae33e99a72ab9fc28927d8123de988d2ef' AND
        down_checksum_sha256='91b6b40573cd5c636810e94d61b0673dffd3034184fda3a8a2fe6d11e35c2e4a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.domain_ownerships') IS NOT NULL OR
            to_regclass(current_schema() || '.site_domain_active') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name = 'domains.security.manage') THEN
        RAISE EXCEPTION 'migration 303 requires the exact verified 302 release head' USING ERRCODE='P3030';
    END IF;
END;
$migration_303_up$;

-- Domain trust (v6.1.0 #11 blocklist, #12 ownership verification, G8-d):
--   * platform_domain_blocklist: admin-maintained root (domain and every
--     subdomain) or exact patterns; site writes reject hits with
--     domain_blocked and never reveal the reason.
--   * domain_ownerships: a tenant scope proves an apex (eTLD+1) by DNS TXT
--     (_cdnca-verify.<apex>) or an HTTP file. At most one scope holds a
--     verified apex.
--   * domain_claim_suspensions: a verified owner claimed a domain another
--     scope still served; that site is disabled and cannot be re-enabled
--     until the domain leaves it or a platform administrator releases it.
--   * site_domain_active: current-state projection of the append-only
--     site_domain_facts so the overlap guard is an index lookup under a
--     per-domain-family advisory lock instead of a full DISTINCT ON scan
--     under one global lock.
INSERT INTO permissions(name, description)
VALUES ('domains.security.manage', 'Manage the domain blocklist, ownership records and claim suspensions');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'domains.security.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

-- The family of a domain is the name a wildcard would have to be rooted at to
-- cover it: www.a.com -> a.com, *.a.com -> a.com. Overlaps only exist inside a
-- family (equal names, or a wildcard and its direct children).
CREATE FUNCTION site_domain_family_299(domain text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT CASE WHEN domain LIKE '*.%' THEN substring(domain FROM 3)
                ELSE substring(domain FROM position('.' IN domain) + 1) END
$$;

-- Locks every key an activation of the given domains can conflict on, in one
-- sorted pass so concurrent writers cannot deadlock. An exact name takes its
-- own key exclusively and its family shared (siblings do not serialize); a
-- wildcard takes both exclusively (it conflicts with every direct child).
CREATE FUNCTION lock_site_domains_299(domains text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    item record;
BEGIN
    FOR item IN
        SELECT key, bool_or(exclusive) AS exclusive FROM (
            SELECT 'n:' || regexp_replace(domain, '^\*\.', '') AS key, true AS exclusive
            FROM unnest(domains) domain WHERE domain NOT LIKE '*.%'
            UNION ALL
            SELECT 'f:' || site_domain_family_299(domain), domain LIKE '*.%' FROM unnest(domains) domain
            UNION ALL
            SELECT 'w:' || domain, true FROM unnest(domains) domain WHERE domain LIKE '*.%'
        ) keys
        GROUP BY key ORDER BY key
    LOOP
        IF item.exclusive THEN
            PERFORM pg_advisory_xact_lock(299, hashtext(item.key));
        ELSE
            PERFORM pg_advisory_xact_lock_shared(299, hashtext(item.key));
        END IF;
    END LOOP;
END;
$$;

CREATE TABLE site_domain_active (
    canonical_domain text NOT NULL,
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    family_domain text NOT NULL,
    activated_sequence bigint NOT NULL,
    PRIMARY KEY (canonical_domain, scope_id, site_id),
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT
);
CREATE INDEX site_domain_active_family_299_idx ON site_domain_active(family_domain, canonical_domain);
CREATE INDEX site_domain_active_site_299_idx ON site_domain_active(scope_id, site_id);

INSERT INTO site_domain_active(canonical_domain, scope_id, site_id, family_domain, activated_sequence)
SELECT latest.canonical_domain, latest.scope_id, latest.site_id,
       site_domain_family_299(latest.canonical_domain), latest.global_sequence
FROM (
    SELECT DISTINCT ON (scope_id, site_id, canonical_domain)
           scope_id, site_id, canonical_domain, action, global_sequence
    FROM site_domain_facts
    ORDER BY scope_id, site_id, canonical_domain, global_sequence DESC
) latest
WHERE latest.action = 'activate';

CREATE TABLE domain_ownerships (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    apex text NOT NULL CHECK (
        apex = lower(apex) AND length(apex) <= 253 AND
        apex ~ '^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    method text NOT NULL CHECK (method IN ('dns_txt', 'http_file')),
    token text NOT NULL CHECK (token ~ '^[a-f0-9]{48}$'),
    status text NOT NULL CHECK (status IN ('pending', 'verified', 'expired', 'revoked')),
    verified_at timestamptz CHECK (verified_at IS NULL OR isfinite(verified_at)),
    last_checked_at timestamptz CHECK (last_checked_at IS NULL OR isfinite(last_checked_at)),
    next_check_at timestamptz CHECK (next_check_at IS NULL OR isfinite(next_check_at)),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures BETWEEN 0 AND 3),
    last_failure_code text NOT NULL DEFAULT '' CHECK (last_failure_code ~ '^[a-z0-9_]{0,64}$'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (scope_id, apex),
    UNIQUE (id, scope_id),
    CHECK (status <> 'verified' OR (verified_at IS NOT NULL AND next_check_at IS NOT NULL))
);
CREATE UNIQUE INDEX domain_ownerships_verified_apex_299_idx ON domain_ownerships(apex) WHERE status = 'verified';
CREATE INDEX domain_ownerships_due_299_idx ON domain_ownerships(next_check_at) WHERE status = 'verified';

CREATE TABLE domain_claim_suspensions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    canonical_domain text NOT NULL,
    claimant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    claimant_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    ownership_id uuid NOT NULL REFERENCES domain_ownerships(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    released_at timestamptz CHECK (released_at IS NULL OR (isfinite(released_at) AND released_at >= created_at)),
    release_reason text CHECK (release_reason IN ('domain_removed', 'admin_released')),
    released_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    CHECK ((released_at IS NULL) = (release_reason IS NULL)),
    CHECK (scope_id <> claimant_scope_id),
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX domain_claim_suspensions_open_299_idx
    ON domain_claim_suspensions(scope_id, site_id, canonical_domain) WHERE released_at IS NULL;
CREATE INDEX domain_claim_suspensions_created_299_idx ON domain_claim_suspensions(created_at DESC, id DESC);

CREATE TABLE platform_domain_blocklist (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    pattern text NOT NULL UNIQUE CHECK (
        pattern = lower(pattern) AND length(pattern) <= 253 AND
        pattern ~ '^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    match_type text NOT NULL CHECK (match_type IN ('root', 'exact')),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 512 AND reason !~ '[[:cntrl:]]'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0)
);
CREATE INDEX platform_domain_blocklist_created_299_idx ON platform_domain_blocklist(created_at DESC, id DESC);

CREATE TABLE domain_trust_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9._]{0,63}$'),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key)
);

-- G8-d: the 148 overlap guard keeps its name, trigger, SQLSTATE and
-- constraint so callers are unchanged. It now reads the current-state
-- projection under per-family locks and ignores a holder whose domain is
-- suspended by a claim (that holder keeps its facts but no longer serves).
CREATE OR REPLACE FUNCTION guard_site_domain_fact_148()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    candidate_base text := regexp_replace(NEW.canonical_domain, '^\*\.', '');
BEGIN
    IF NEW.action <> 'activate' THEN
        RETURN NEW;
    END IF;
    PERFORM lock_site_domains_299(ARRAY[NEW.canonical_domain]);
    IF EXISTS (
        SELECT 1 FROM site_domain_active active
        WHERE (active.scope_id, active.site_id) <> (NEW.scope_id, NEW.site_id) AND (
            active.canonical_domain = NEW.canonical_domain OR
            (NEW.canonical_domain NOT LIKE '*.%' AND
             active.canonical_domain = '*.' || site_domain_family_299(NEW.canonical_domain)) OR
            (NEW.canonical_domain LIKE '*.%' AND active.family_domain = candidate_base AND
             active.canonical_domain NOT LIKE '*.%')
        ) AND NOT EXISTS (
            SELECT 1 FROM domain_claim_suspensions suspension
            WHERE suspension.scope_id = active.scope_id AND suspension.site_id = active.site_id AND
                  suspension.canonical_domain = active.canonical_domain AND suspension.released_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION 'site domain wildcard overlap'
            USING ERRCODE = '23505', CONSTRAINT = 'site_domain_facts_overlap_148';
    END IF;
    RETURN NEW;
END;
$$;

-- Keeps site_domain_active equal to the latest fact per (site, domain) and
-- releases a claim suspension once its domain leaves the suspended site.
CREATE FUNCTION project_site_domain_fact_299()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.action = 'activate' THEN
        INSERT INTO site_domain_active(canonical_domain, scope_id, site_id, family_domain, activated_sequence)
        VALUES (NEW.canonical_domain, NEW.scope_id, NEW.site_id,
                site_domain_family_299(NEW.canonical_domain), NEW.global_sequence)
        ON CONFLICT (canonical_domain, scope_id, site_id) DO NOTHING;
    ELSE
        DELETE FROM site_domain_active
        WHERE canonical_domain = NEW.canonical_domain AND scope_id = NEW.scope_id AND site_id = NEW.site_id;
        UPDATE domain_claim_suspensions
        SET released_at = NEW.occurred_at, release_reason = 'domain_removed', released_by_user_id = NEW.actor_user_id
        WHERE scope_id = NEW.scope_id AND site_id = NEW.site_id AND
              canonical_domain = NEW.canonical_domain AND released_at IS NULL;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER site_domain_facts_project_299
AFTER INSERT ON site_domain_facts
FOR EACH ROW EXECUTE FUNCTION project_site_domain_fact_299();

-- A suspended site stays disabled. Deferred so a single write may drop the
-- claimed domain (releasing the suspension) and re-enable the site.
CREATE FUNCTION guard_site_claim_suspension_299()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sites site
        WHERE site.id = NEW.id AND site.enabled AND site.deleted_at IS NULL AND EXISTS (
            SELECT 1 FROM domain_claim_suspensions suspension
            WHERE suspension.scope_id = site.scope_id AND suspension.site_id = site.id AND
                  suspension.released_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION 'site has a domain suspended by an ownership claim'
            USING ERRCODE = 'P3032', CONSTRAINT = 'sites_domain_claim_suspended_299';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER sites_domain_claim_suspended_299
AFTER INSERT OR UPDATE OF enabled ON sites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.enabled) EXECUTE FUNCTION guard_site_claim_suspension_299();

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at)
VALUES
    ('domain.claim.suspended.zh-cn', 1, 'sms', '',
     '您的网站域名{{.domain}}已被完成所有权验证的账户认领，相关网站已停用。如有异议请联系管理员申诉。',
     ARRAY['domain'], '2026-10-17 00:00:00+00'),
    ('domain.claim.suspended.zh-cn', 1, 'email', '网站域名已被认领',
     '您的网站域名{{.domain}}已被完成所有权验证的账户认领，使用该域名的网站已自动停用。删除该域名后可重新启用网站；如有异议请联系平台管理员申诉。',
     ARRAY['domain'], '2026-10-17 00:00:00+00'),
    ('domain.claim.completed.zh-cn', 1, 'sms', '',
     '域名{{.domain}}认领完成，已停用{{.site_count}}个冲突网站。',
     ARRAY['domain','site_count'], '2026-10-17 00:00:00+00'),
    ('domain.claim.completed.zh-cn', 1, 'email', '域名认领完成',
     '域名{{.domain}}认领完成，其他账户的{{.site_count}}个冲突网站已自动停用，您现在可以添加该域名。',
     ARRAY['domain','site_count'], '2026-10-17 00:00:00+00'),
    ('domain.ownership.expired.zh-cn', 1, 'sms', '',
     '域名{{.apex}}所有权复验连续失败，验证已失效，请重新验证。',
     ARRAY['apex'], '2026-10-17 00:00:00+00'),
    ('domain.ownership.expired.zh-cn', 1, 'email', '域名所有权验证已失效',
     '域名{{.apex}}的所有权复验连续三次失败，验证状态已失效，网站不受影响。请检查 TXT 记录后重新验证，以免该域名被其他账户验证。',
     ARRAY['apex'], '2026-10-17 00:00:00+00')
ON CONFLICT (template_id, version, channel) DO NOTHING;

REVOKE ALL ON site_domain_active, domain_ownerships, domain_claim_suspensions,
    platform_domain_blocklist, domain_trust_write_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION site_domain_family_299(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lock_site_domains_299(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION project_site_domain_fact_299() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_site_claim_suspension_299() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION site_domain_family_299(text), lock_site_domains_299(text[])
    TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON site_domain_active TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON domain_ownerships, domain_claim_suspensions, domain_trust_write_requests
    TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON platform_domain_blocklist TO cdnca_control_app, cdnca_control_runtime;
