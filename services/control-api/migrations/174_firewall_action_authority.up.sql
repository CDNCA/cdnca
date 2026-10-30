LOCK TABLE schema_migrations,permissions,roles,role_permissions,sites IN ACCESS EXCLUSIVE MODE;

DO $migration_174$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>173 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>173 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=173 AND migration_id='173_l2_topology_identity' AND
              checksum_sha256='fa59baaceb977e0973c1061b9d9028e835de54a0be9e86dbec88780aced1e970' AND
              down_checksum_sha256='b7552564c765cf59cdbba3eba7b08c50e4cbcd9ccbfd9b4999158e1641744b3a' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (SELECT 1 FROM permissions WHERE name='firewall.read') OR
         NOT EXISTS (SELECT 1 FROM permissions WHERE name='firewall.manage') OR
         to_regclass('firewall_action_policy_heads') IS NOT NULL OR
         to_regclass('firewall_action_policy_revisions') IS NOT NULL OR
         to_regclass('firewall_action_write_receipts') IS NOT NULL OR
         to_regclass('firewall_action_publication_outbox') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 174 requires the exact verified 173 release head and firewall RBAC contract'
            USING ERRCODE='P1740';
    END IF;
END;
$migration_174$;

CREATE TABLE firewall_action_policy_heads (
    id uuid NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
    document_bytes bytea NOT NULL CHECK(octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK(
        octet_length(document_sha256)=32 AND document_sha256=sha256(document_bytes) AND
        document=convert_from(document_bytes,'UTF8')::jsonb
    ),
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    active_revision bigint NOT NULL DEFAULT 0 CHECK(active_revision BETWEEN 0 AND 9007199254740991),
    lkg_revision bigint NOT NULL DEFAULT 0 CHECK(lkg_revision BETWEEN 0 AND 9007199254740991),
    deployment_state text NOT NULL CHECK(deployment_state IN ('pending','active','failed')),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY(tenant_scope_id,site_id),
    UNIQUE(tenant_scope_id,site_id,id),
    FOREIGN KEY(tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    CHECK(
        (deployment_state='active' AND active_revision=revision AND lkg_revision=revision) OR
        (deployment_state IN ('pending','failed') AND active_revision<revision AND lkg_revision=active_revision)
    )
);

CREATE TABLE firewall_action_policy_revisions (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    policy_id uuid NOT NULL,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
    document_bytes bytea NOT NULL CHECK(octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK(
        octet_length(document_sha256)=32 AND document_sha256=sha256(document_bytes) AND
        document=convert_from(document_bytes,'UTF8')::jsonb
    ),
    expected_active_revision bigint NOT NULL CHECK(expected_active_revision>=0 AND expected_active_revision<revision),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK(request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,site_id,revision),
    UNIQUE(tenant_scope_id,site_id,policy_id,revision),
    FOREIGN KEY(tenant_scope_id,site_id,policy_id)
        REFERENCES firewall_action_policy_heads(tenant_scope_id,site_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

ALTER TABLE firewall_action_policy_heads
    ADD CONSTRAINT firewall_action_policy_heads_current_revision_174
    FOREIGN KEY(tenant_scope_id,site_id,id,revision)
    REFERENCES firewall_action_policy_revisions(tenant_scope_id,site_id,policy_id,revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE firewall_action_write_receipts (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=65536),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,site_id,idempotency_key),
    FOREIGN KEY(tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE firewall_action_publication_outbox (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
    document_bytes bytea NOT NULL CHECK(octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK(
        octet_length(document_sha256)=32 AND document_sha256=sha256(document_bytes) AND
        document=convert_from(document_bytes,'UTF8')::jsonb
    ),
    state text NOT NULL CHECK(state IN ('pending','projecting','retryable','published','acked','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 16),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    claim_expires_at timestamptz CHECK(claim_expires_at IS NULL OR isfinite(claim_expires_at)),
    projected_at timestamptz CHECK(projected_at IS NULL OR isfinite(projected_at)),
    acknowledged_at timestamptz CHECK(acknowledged_at IS NULL OR isfinite(acknowledged_at)),
    last_error text CHECK(last_error IS NULL OR last_error ~ '^[a-z][a-z0-9_]{0,63}$'),
    outcome_reason text CHECK(outcome_reason IS NULL OR outcome_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(tenant_scope_id,site_id,policy_id,revision)
        REFERENCES firewall_action_policy_revisions(tenant_scope_id,site_id,policy_id,revision) ON DELETE RESTRICT,
    UNIQUE(tenant_scope_id,site_id,revision),
    UNIQUE(tenant_scope_id,site_id,id,policy_id,revision),
    CHECK((state='pending' AND attempts=0) OR (state<>'pending' AND attempts>0)),
    CHECK((state='projecting')=(claim_expires_at IS NOT NULL)),
    CHECK(claim_expires_at IS NULL OR claim_expires_at>updated_at),
    CHECK((state IN ('published','acked') OR state='failed' AND acknowledged_at IS NOT NULL)=(projected_at IS NOT NULL)),
    CHECK((state='acked' OR state='failed' AND outcome_reason IS NOT NULL)=(acknowledged_at IS NOT NULL)),
    CHECK((state='retryable')=(last_error IS NOT NULL AND acknowledged_at IS NULL) OR state<>'retryable'),
    CHECK((state='acked' AND outcome_reason IS NOT NULL) OR state<>'acked')
);

CREATE INDEX firewall_action_publication_ready_174_idx
    ON firewall_action_publication_outbox(available_at,id)
    WHERE state IN ('pending','retryable','projecting');

CREATE FUNCTION prevent_firewall_action_fact_mutation_174()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P1741';
END;
$$;

CREATE FUNCTION prevent_firewall_action_fact_truncate_174()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% cannot be truncated',TG_TABLE_NAME USING ERRCODE='P1741';
END;
$$;

CREATE FUNCTION guard_firewall_action_head_174()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.created_at) OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'firewall action head identity is immutable' USING ERRCODE='P1742';
    END IF;
    IF NEW.revision=OLD.revision+1 THEN
        IF NEW.deployment_state<>'pending' OR NEW.active_revision<>OLD.active_revision OR NEW.lkg_revision<>OLD.lkg_revision THEN
            RAISE EXCEPTION 'firewall action candidate must preserve active LKG' USING ERRCODE='P1743';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revision=OLD.revision AND OLD.deployment_state='pending' AND NEW.deployment_state IN ('active','failed') AND
       NEW.document_bytes=OLD.document_bytes AND NEW.document_sha256=OLD.document_sha256 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid firewall action head transition' USING ERRCODE='P1744';
END;
$$;

CREATE FUNCTION guard_firewall_action_outbox_174()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.policy_id,NEW.revision,
        NEW.document_bytes,NEW.document_sha256,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.policy_id,OLD.revision,
        OLD.document_bytes,OLD.document_sha256,OLD.created_at) OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'firewall action publication identity is immutable' USING ERRCODE='P1745';
    END IF;
    IF OLD.state IN ('pending','retryable') AND NEW.state='projecting' AND NEW.attempts=OLD.attempts+1 THEN RETURN NEW; END IF;
    IF OLD.state='projecting' AND NEW.state='projecting' AND NEW.attempts=OLD.attempts+1 AND OLD.claim_expires_at<=NEW.updated_at THEN RETURN NEW; END IF;
    IF OLD.state='projecting' AND NEW.state IN ('retryable','published','failed') AND NEW.attempts=OLD.attempts THEN RETURN NEW; END IF;
    IF OLD.state='published' AND NEW.state IN ('acked','failed') AND NEW.attempts=OLD.attempts THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'invalid firewall action publication transition' USING ERRCODE='P1746';
END;
$$;

CREATE TRIGGER firewall_action_revisions_immutable_174
BEFORE UPDATE OR DELETE ON firewall_action_policy_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_firewall_action_fact_mutation_174();
CREATE TRIGGER firewall_action_receipts_immutable_174
BEFORE UPDATE OR DELETE ON firewall_action_write_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_firewall_action_fact_mutation_174();
CREATE TRIGGER firewall_action_head_guard_174
BEFORE UPDATE OR DELETE ON firewall_action_policy_heads
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_head_174();
CREATE TRIGGER firewall_action_outbox_guard_174
BEFORE UPDATE OR DELETE ON firewall_action_publication_outbox
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_outbox_174();

CREATE TRIGGER firewall_action_revisions_no_truncate_174
BEFORE TRUNCATE ON firewall_action_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();
CREATE TRIGGER firewall_action_receipts_no_truncate_174
BEFORE TRUNCATE ON firewall_action_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();
CREATE TRIGGER firewall_action_heads_no_truncate_174
BEFORE TRUNCATE ON firewall_action_policy_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();
CREATE TRIGGER firewall_action_outbox_no_truncate_174
BEFORE TRUNCATE ON firewall_action_publication_outbox
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();

REVOKE ALL ON firewall_action_policy_heads,firewall_action_policy_revisions,
    firewall_action_write_receipts,firewall_action_publication_outbox FROM PUBLIC;
