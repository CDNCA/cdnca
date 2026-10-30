LOCK TABLE schema_migrations, autodefense_signatures, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_415_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 414 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 414 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=414 AND
        migration_id='414_autodefense_module_values' AND
        checksum_sha256='75d44f0f16cd29ddcb04f3e417f0ff47bb9df2182ecaf176a3572d7dd2fc3fad' AND
        down_checksum_sha256='cc72a3ecc92418b64e244a16086756e42771dd76374130dd481b3a07173085f5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.autodefense_signature_sightings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 415 requires the exact verified 414 release head' USING ERRCODE='P4150';
    END IF;
END;
$migration_415_up$;

-- 415（r136 ad-10，占位号，合入时改号）。Signature evaluation and
-- federation on the control plane (ADR 0010 section 6.2 / 8.3; node
-- autonomy, user 10-19 06:20: the control plane is off the reaction path and
-- only broadcasts small signatures; Q7: cross-tenant intelligence only adds
-- score).

-- Evaluation of each site signature over every node and site that reported
-- it, and the user-layer rule pack a solidified signature became (Q4).
-- Links recorded before 415 never wrote a rule: they return to automatic
-- management.
UPDATE autodefense_signatures SET managed=true, solidified_kind=NULL, solidified_rule_id=NULL WHERE solidified_kind IS NOT NULL;
ALTER TABLE autodefense_signatures
    ADD COLUMN evaluation text NOT NULL DEFAULT 'pending' CHECK (evaluation IN ('pending', 'qualified', 'rejected', 'withdrawn')),
    ADD COLUMN confidence_permille bigint NOT NULL DEFAULT 0 CHECK (confidence_permille BETWEEN 0 AND 1000),
    ADD COLUMN node_count bigint NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    ADD COLUMN site_count bigint NOT NULL DEFAULT 0 CHECK (site_count >= 0),
    ADD COLUMN misfire_ppm bigint NOT NULL DEFAULT 0 CHECK (misfire_ppm BETWEEN 0 AND 1000000),
    ADD COLUMN evaluation_reason text NOT NULL DEFAULT '' CHECK (char_length(evaluation_reason) <= 512),
    ADD COLUMN evaluated_at timestamptz CHECK (evaluated_at IS NULL OR isfinite(evaluated_at)),
    ADD COLUMN last_seen_at timestamptz CHECK (last_seen_at IS NULL OR isfinite(last_seen_at)),
    ADD COLUMN solidified_pack_id text CHECK (solidified_pack_id IS NULL OR char_length(solidified_pack_id) BETWEEN 1 AND 160),
    ADD COLUMN solidified_version text CHECK (solidified_version IS NULL OR solidified_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    ADD CONSTRAINT autodefense_signatures_solidified_415 CHECK (
        (solidified_kind IS NULL) = (solidified_pack_id IS NULL) AND (solidified_pack_id IS NULL) = (solidified_version IS NULL));
CREATE INDEX autodefense_signatures_evaluation_415 ON autodefense_signatures (tenant_scope_id, id) WHERE evaluation <> 'pending';

-- One row per (site signature, reporting node): the statistics the node
-- measured on its own normal reservoir.
CREATE TABLE autodefense_signature_sightings (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    signature_id text NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    cover_permille bigint NOT NULL CHECK (cover_permille BETWEEN 0 AND 1000),
    fpr_ppm bigint NOT NULL CHECK (fpr_ppm BETWEEN 0 AND 1000000),
    lift_milli bigint NOT NULL CHECK (lift_milli >= 0),
    attack_samples bigint NOT NULL CHECK (attack_samples >= 0),
    normal_samples bigint NOT NULL CHECK (normal_samples >= 0),
    first_seen_at timestamptz NOT NULL CHECK (isfinite(first_seen_at)),
    last_seen_at timestamptz NOT NULL CHECK (isfinite(last_seen_at) AND last_seen_at >= first_seen_at),
    PRIMARY KEY (tenant_scope_id, site_id, signature_id, node_id),
    FOREIGN KEY (tenant_scope_id, site_id, signature_id) REFERENCES autodefense_signatures(tenant_scope_id, site_id, id) ON DELETE CASCADE
);
CREATE INDEX autodefense_signature_sightings_seen_415 ON autodefense_signature_sightings (last_seen_at);
INSERT INTO autodefense_signature_sightings(tenant_scope_id,site_id,signature_id,node_id,cover_permille,fpr_ppm,lift_milli,
    attack_samples,normal_samples,first_seen_at,last_seen_at)
SELECT tenant_scope_id, site_id, id, origin_node_id, cover_permille, fpr_ppm, 0, hits, 0, created_at, updated_at
FROM autodefense_signatures WHERE origin_node_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM nodes WHERE nodes.id=autodefense_signatures.origin_node_id);

-- What the evaluator broadcasts to the nodes of each site (snapshot
-- signatures and tenant federation mitigations, contract section 3.4/3.5);
-- the distributor reads it, digest is part of its build fingerprint.
CREATE TABLE autodefense_site_federation (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    signatures jsonb NOT NULL CHECK (jsonb_typeof(signatures) = 'array' AND jsonb_array_length(signatures) <= 32),
    mitigations jsonb NOT NULL CHECK (jsonb_typeof(mitigations) = 'array' AND jsonb_array_length(mitigations) <= 4096),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

-- Platform intelligence (section 8.3 row 3, Q7): an address or network
-- judged L3 on at least three tenants only adds bonus to a client's score.
CREATE TABLE autodefense_platform_intel (
    kind text NOT NULL CHECK (kind IN ('ip', 'cidr')),
    value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 64),
    bonus smallint NOT NULL CHECK (bonus BETWEEN 1 AND 100),
    tenants bigint NOT NULL CHECK (tenants >= 1),
    until timestamptz NOT NULL CHECK (isfinite(until)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (kind, value)
);

-- Same-site cross-node L3/L4: the evaluator lists the bans on the security
-- ban list (ge-waf S5, source autodefense). Tenant scope is L2 at most and
-- platform scope never bans (section 8.3, Q7), so every autodefense entry is
-- a site entry and no scope column is needed.
ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_source_check;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_source_415
    CHECK (source IN ('waf', 'cc', 'manual', 'autodefense'));

REVOKE ALL ON autodefense_signature_sightings, autodefense_site_federation, autodefense_platform_intel FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_signature_sightings, autodefense_site_federation, autodefense_platform_intel
    TO cdnca_control_app, cdnca_control_runtime;
