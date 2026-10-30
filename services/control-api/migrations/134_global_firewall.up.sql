LOCK TABLE schema_migrations,permissions,roles,role_permissions,firewall_command_outbox
IN ACCESS EXCLUSIVE MODE;

DO $migration_134$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 133 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 133 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=133 AND migration_id='133_billing_recharge_reconciliation'
          AND checksum_sha256='76ba0e368ebb22f2999390e97ae67ef2d6503d290b774297fcfb3e0b36d3239a'
          AND down_checksum_sha256='4ef8c05daab2459925f6e1e3edf2afd3b6a50e3d8e6536ed29c70bf2794abe30'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('global_firewall_policies') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 134 requires the exact verified 133 release head' USING ERRCODE='P1340';
    END IF;
END;
$migration_134$;

INSERT INTO permissions(name,description) VALUES
    ('firewall.read','Read the tenant global firewall policy and hit history'),
    ('firewall.manage','Create, publish, and recover the tenant global firewall policy');

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
CROSS JOIN (VALUES('firewall.read'),('firewall.manage')) permission(name)
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind IN ('tenant','platform')
WHERE role.system_role AND role.name IN ('tenant_owner','platform_owner')
ON CONFLICT DO NOTHING;

CREATE TABLE global_firewall_policies (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL UNIQUE REFERENCES access_scopes(id) ON DELETE RESTRICT,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    revision bigint NOT NULL CHECK(revision>0),
    active_revision bigint NOT NULL DEFAULT 0 CHECK(active_revision>=0 AND active_revision<=revision),
    deployment_state text NOT NULL CHECK(deployment_state IN ('pending','canary','active','partial','failed','rolled_back')),
    active_sha256 bytea CHECK(active_sha256 IS NULL OR octet_length(active_sha256)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(tenant_scope_id,id),
    CHECK((active_revision=0)=(active_sha256 IS NULL))
);

CREATE TABLE global_firewall_policy_revisions (
    tenant_scope_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    policy_id uuid NOT NULL,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    operation text NOT NULL CHECK(operation IN ('apply','recover')),
    recovery_of_revision bigint,
    recovery_reason text,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK(request_id ~ '^[0-9a-f-]{36}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,revision),
    FOREIGN KEY(tenant_scope_id,policy_id) REFERENCES global_firewall_policies(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(tenant_scope_id,policy_id,revision),
    CHECK((operation='apply' AND recovery_of_revision IS NULL AND recovery_reason IS NULL) OR
          (operation='recover' AND recovery_of_revision>0 AND recovery_of_revision<revision AND
           recovery_reason IN ('false_positive','health_failure','operator_request')))
);

CREATE TABLE global_firewall_write_receipts (
    tenant_scope_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=65536),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,idempotency_key),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE global_firewall_publication_outbox (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    operation text NOT NULL CHECK(operation IN ('apply','recover')),
    recovery_reason text,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    state text NOT NULL CHECK(state IN ('pending','retryable','projected','active','partial','failed','rolled_back')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 16),
    available_at timestamptz NOT NULL,
    projected_at timestamptz,
    last_error text CHECK(last_error IS NULL OR char_length(last_error)<=2048),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(tenant_scope_id,policy_id,revision)
        REFERENCES global_firewall_policy_revisions(tenant_scope_id,policy_id,revision) ON DELETE RESTRICT,
    UNIQUE(tenant_scope_id,revision),
    UNIQUE(tenant_scope_id,id,policy_id,revision),
    CHECK((operation='apply' AND recovery_reason IS NULL) OR
          (operation='recover' AND recovery_reason IN ('false_positive','health_failure','operator_request'))),
    CHECK((state IN ('projected','active','partial','failed','rolled_back'))=(projected_at IS NOT NULL))
);

CREATE INDEX global_firewall_publication_ready_idx
    ON global_firewall_publication_outbox(available_at,id) WHERE state IN ('pending','retryable');

CREATE FUNCTION prevent_global_firewall_fact_mutation_134()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P1341';
END;
$$;

CREATE TRIGGER global_firewall_revisions_append_only
BEFORE UPDATE OR DELETE ON global_firewall_policy_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_global_firewall_fact_mutation_134();
CREATE TRIGGER global_firewall_receipts_append_only
BEFORE UPDATE OR DELETE ON global_firewall_write_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_global_firewall_fact_mutation_134();

CREATE FUNCTION prevent_global_firewall_fact_truncate_134()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% cannot be truncated',TG_TABLE_NAME USING ERRCODE='P1341';
END;
$$;

CREATE TRIGGER global_firewall_revisions_no_truncate
BEFORE TRUNCATE ON global_firewall_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_global_firewall_fact_truncate_134();
CREATE TRIGGER global_firewall_receipts_no_truncate
BEFORE TRUNCATE ON global_firewall_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_global_firewall_fact_truncate_134();

CREATE FUNCTION protect_global_firewall_publication_134()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.policy_id,NEW.revision,NEW.operation,
        NEW.recovery_reason,NEW.document,NEW.document_sha256,NEW.created_at) IS DISTINCT FROM
        ROW(OLD.id,OLD.tenant_scope_id,OLD.policy_id,OLD.revision,OLD.operation,
        OLD.recovery_reason,OLD.document,OLD.document_sha256,OLD.created_at) THEN
        RAISE EXCEPTION 'global firewall publication identity is immutable' USING ERRCODE='P1341';
    END IF;
    IF NOT ((OLD.state='pending' AND NEW.state IN ('retryable','projected')) OR
            (OLD.state='retryable' AND NEW.state IN ('retryable','projected')) OR
            (OLD.state='projected' AND NEW.state IN ('active','partial','failed','rolled_back'))) THEN
        RAISE EXCEPTION 'invalid global firewall publication transition' USING ERRCODE='P1341';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER global_firewall_publication_guard
BEFORE UPDATE OR DELETE ON global_firewall_publication_outbox
FOR EACH ROW EXECUTE FUNCTION protect_global_firewall_publication_134();
CREATE TRIGGER global_firewall_publication_no_truncate
BEFORE TRUNCATE ON global_firewall_publication_outbox
FOR EACH STATEMENT EXECUTE FUNCTION prevent_global_firewall_fact_truncate_134();

DROP TRIGGER firewall_command_outbox_binding_valid ON firewall_command_outbox;
DROP FUNCTION validate_firewall_command_outbox_binding();
DROP TRIGGER firewall_command_outbox_mutation ON firewall_command_outbox;
DROP FUNCTION protect_firewall_command_outbox_mutation();

ALTER TABLE firewall_command_outbox
    DROP CONSTRAINT firewall_command_outbox_policy_kind_check,
    DROP CONSTRAINT firewall_command_outbox_publication_id_node_id_key,
    DROP CONSTRAINT firewall_command_outbox_tenant_scope_id_binding_id_fkey,
    DROP CONSTRAINT firewall_command_outbox_tenant_scope_id_publication_id_bin_fkey,
    DROP CONSTRAINT firewall_command_outbox_tenant_scope_id_policy_id_policy_k_fkey,
    ALTER COLUMN binding_id DROP NOT NULL,
    ADD COLUMN global_revision bigint,
    ADD COLUMN terminal_state text,
    ADD COLUMN active_policy_version bigint,
    ADD CONSTRAINT firewall_command_outbox_policy_kind_check CHECK(policy_kind IN ('waf','cc','acl','global')),
    ADD CONSTRAINT firewall_command_outbox_global_revision_check CHECK(global_revision IS NULL OR global_revision>0),
    ADD CONSTRAINT firewall_command_outbox_terminal_state_check CHECK(terminal_state IS NULL OR terminal_state IN ('applied','failed','rolled_back')),
    ADD CONSTRAINT firewall_command_outbox_active_policy_version_check CHECK(active_policy_version IS NULL OR active_policy_version>=0),
    ADD CONSTRAINT firewall_command_outbox_publication_node_site_key UNIQUE(publication_id,node_id,site_id),
    ADD CONSTRAINT firewall_command_outbox_scope_shape_134 CHECK(
        (policy_kind='global' AND binding_id IS NULL AND global_revision IS NOT NULL) OR
        (policy_kind<>'global' AND binding_id IS NOT NULL AND global_revision IS NULL)),
    ADD CONSTRAINT firewall_command_outbox_terminal_shape_134 CHECK(
        (state='acked')=(acked_at IS NOT NULL AND terminal_state IS NOT NULL AND active_policy_version IS NOT NULL));

ALTER TABLE firewall_command_outbox
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_id_binding_id_fkey
        FOREIGN KEY(tenant_scope_id,binding_id) REFERENCES security_policy_site_bindings(tenant_scope_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_publication_binding_fkey
        FOREIGN KEY(tenant_scope_id,publication_id,binding_id) REFERENCES security_policy_publications(tenant_scope_id,id,binding_id) ON DELETE RESTRICT,
    ADD CONSTRAINT firewall_command_outbox_tenant_policy_kind_fkey
        FOREIGN KEY(tenant_scope_id,policy_id,policy_kind) REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT;

CREATE FUNCTION protect_firewall_command_outbox_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'firewall command outbox facts are append-only';
    END IF;
    IF ROW(NEW.id,NEW.installation_id,NEW.tenant_scope_id,NEW.site_id,NEW.policy_id,NEW.policy_kind,NEW.binding_id,
           NEW.publication_id,NEW.node_id,NEW.policy_version,NEW.expected_active_policy_version,NEW.global_revision,
           NEW.idempotency_key,NEW.command_bytes,NEW.command_sha256,NEW.publication_bundle_sha256,
           NEW.canonical_payload_sha256,NEW.runtime_snapshot_sha256,NEW.signing_key_id,NEW.signature_algorithm,
           NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.installation_id,OLD.tenant_scope_id,OLD.site_id,
           OLD.policy_id,OLD.policy_kind,OLD.binding_id,OLD.publication_id,OLD.node_id,OLD.policy_version,
           OLD.expected_active_policy_version,OLD.global_revision,OLD.idempotency_key,OLD.command_bytes,OLD.command_sha256,
           OLD.publication_bundle_sha256,OLD.canonical_payload_sha256,OLD.runtime_snapshot_sha256,
           OLD.signing_key_id,OLD.signature_algorithm,OLD.created_at) THEN
        RAISE EXCEPTION 'firewall command outbox command identity is immutable';
    END IF;
    IF NOT ((OLD.state='pending' AND NEW.state IN ('published','retryable','failed')) OR
            (OLD.state='retryable' AND NEW.state IN ('pending','published','failed')) OR
            (OLD.state='published' AND NEW.state IN ('acked','retryable','failed'))) THEN
        RAISE EXCEPTION 'invalid firewall command outbox state transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_mutation
BEFORE UPDATE OR DELETE ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION protect_firewall_command_outbox_mutation();

CREATE FUNCTION validate_firewall_command_outbox_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE publication record;
BEGIN
    IF NEW.policy_kind='global' THEN
        SELECT p.tenant_scope_id,p.policy_id,p.revision,p.document_sha256 INTO publication
        FROM global_firewall_publication_outbox p
        WHERE p.tenant_scope_id=NEW.tenant_scope_id AND p.id=NEW.publication_id
          AND p.policy_id=NEW.policy_id AND p.revision=NEW.global_revision
        FOR SHARE OF p;
        IF NOT FOUND OR publication.document_sha256<>NEW.publication_bundle_sha256 OR
           publication.document_sha256<>NEW.canonical_payload_sha256 OR
           publication.document_sha256<>NEW.runtime_snapshot_sha256 THEN
            RAISE EXCEPTION 'global firewall command publication mismatch' USING ERRCODE='P1342';
        END IF;
    ELSE
        SELECT p.tenant_scope_id,p.site_id,p.policy_id,p.policy_kind,p.policy_version,p.expected_active_version,
               p.bundle_sha256,p.canonical_payload_sha256,p.runtime_snapshot_sha256,p.signing_key_id,
               t.node_id INTO publication
        FROM security_policy_publications p
        JOIN security_policy_publication_targets t ON t.tenant_scope_id=p.tenant_scope_id AND
            t.publication_id=p.id AND t.binding_id=p.binding_id
        WHERE p.tenant_scope_id=NEW.tenant_scope_id AND p.id=NEW.publication_id AND p.binding_id=NEW.binding_id
          AND t.node_id=NEW.node_id AND t.released_at IS NULL
        FOR SHARE OF p,t;
        IF NOT FOUND OR publication.tenant_scope_id<>NEW.tenant_scope_id OR publication.site_id<>NEW.site_id OR
           publication.policy_id<>NEW.policy_id OR publication.policy_kind<>NEW.policy_kind OR
           publication.policy_version<>NEW.policy_version OR
           publication.expected_active_version<>NEW.expected_active_policy_version OR
           publication.bundle_sha256<>NEW.publication_bundle_sha256 OR
           publication.canonical_payload_sha256<>NEW.canonical_payload_sha256 OR
           publication.runtime_snapshot_sha256<>NEW.runtime_snapshot_sha256 OR
           publication.signing_key_id<>NEW.signing_key_id THEN
            RAISE EXCEPTION 'firewall command outbox publication scope or target mismatch' USING ERRCODE='P1111';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_binding_valid
BEFORE INSERT ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION validate_firewall_command_outbox_binding();

REVOKE ALL ON global_firewall_policies,global_firewall_policy_revisions,
    global_firewall_write_receipts,global_firewall_publication_outbox FROM PUBLIC;
