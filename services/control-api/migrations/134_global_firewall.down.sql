-- migration 134 rollback requires the verified 134 head
LOCK TABLE schema_migrations,global_firewall_policies,global_firewall_policy_revisions,
    global_firewall_write_receipts,global_firewall_publication_outbox,firewall_command_outbox,
    permissions,role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_134$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>134 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>134 OR EXISTS(
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS(
        SELECT 1 FROM schema_migrations WHERE version=134 AND migration_id='134_global_firewall'
          AND checksum_sha256='cedf471ecef9136cf9480b298d2dfb9dcdfb98c6bd34011c5d3a56d649bd1624'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS(
        SELECT 1 FROM schema_migrations WHERE version=133 AND migration_id='133_billing_recharge_reconciliation'
          AND checksum_sha256='76ba0e368ebb22f2999390e97ae67ef2d6503d290b774297fcfb3e0b36d3239a'
          AND down_checksum_sha256='4ef8c05daab2459925f6e1e3edf2afd3b6a50e3d8e6536ed29c70bf2794abe30'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR
       EXISTS(SELECT 1 FROM global_firewall_policies LIMIT 1) OR
       EXISTS(SELECT 1 FROM global_firewall_policy_revisions LIMIT 1) OR
       EXISTS(SELECT 1 FROM global_firewall_write_receipts LIMIT 1) OR
       EXISTS(SELECT 1 FROM global_firewall_publication_outbox LIMIT 1) OR
       EXISTS(SELECT 1 FROM firewall_command_outbox WHERE policy_kind='global' LIMIT 1) THEN
        RAISE EXCEPTION 'migration 134 rollback would discard global firewall facts' USING ERRCODE='P1340';
    END IF;
END;
$migration_134$;

DROP TRIGGER firewall_command_outbox_binding_valid ON firewall_command_outbox;
DROP FUNCTION validate_firewall_command_outbox_binding();
DROP TRIGGER firewall_command_outbox_mutation ON firewall_command_outbox;
DROP FUNCTION protect_firewall_command_outbox_mutation();

ALTER TABLE firewall_command_outbox
    DROP CONSTRAINT firewall_command_outbox_tenant_scope_id_binding_id_fkey,
    DROP CONSTRAINT firewall_command_outbox_tenant_scope_publication_binding_fkey,
    DROP CONSTRAINT firewall_command_outbox_tenant_policy_kind_fkey,
    DROP CONSTRAINT firewall_command_outbox_policy_kind_check,
    DROP CONSTRAINT firewall_command_outbox_global_revision_check,
    DROP CONSTRAINT firewall_command_outbox_terminal_state_check,
    DROP CONSTRAINT firewall_command_outbox_active_policy_version_check,
    DROP CONSTRAINT firewall_command_outbox_publication_node_site_key,
    DROP CONSTRAINT firewall_command_outbox_scope_shape_134,
    DROP CONSTRAINT firewall_command_outbox_terminal_shape_134,
    DROP COLUMN global_revision,
    DROP COLUMN terminal_state,
    DROP COLUMN active_policy_version,
    ALTER COLUMN binding_id SET NOT NULL,
    ADD CONSTRAINT firewall_command_outbox_policy_kind_check CHECK(policy_kind IN ('waf','cc','acl')),
    ADD CONSTRAINT firewall_command_outbox_publication_id_node_id_key UNIQUE(publication_id,node_id),
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_id_binding_id_fkey
        FOREIGN KEY(tenant_scope_id,binding_id) REFERENCES security_policy_site_bindings(tenant_scope_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_id_publication_id_bin_fkey
        FOREIGN KEY(tenant_scope_id,publication_id,binding_id) REFERENCES security_policy_publications(tenant_scope_id,id,binding_id) ON DELETE RESTRICT,
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_id_policy_id_policy_k_fkey
        FOREIGN KEY(tenant_scope_id,policy_id,policy_kind) REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT;

CREATE FUNCTION protect_firewall_command_outbox_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'firewall command outbox facts are append-only';
    END IF;
    IF ROW(NEW.id,NEW.installation_id,NEW.tenant_scope_id,NEW.site_id,NEW.policy_id,NEW.policy_kind,NEW.binding_id,
           NEW.publication_id,NEW.node_id,NEW.policy_version,NEW.expected_active_policy_version,
           NEW.idempotency_key,NEW.command_bytes,NEW.command_sha256,NEW.publication_bundle_sha256,
           NEW.canonical_payload_sha256,NEW.runtime_snapshot_sha256,NEW.signing_key_id,NEW.signature_algorithm,
           NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.installation_id,OLD.tenant_scope_id,OLD.site_id,
           OLD.policy_id,OLD.policy_kind,OLD.binding_id,OLD.publication_id,OLD.node_id,OLD.policy_version,
           OLD.expected_active_policy_version,OLD.idempotency_key,OLD.command_bytes,OLD.command_sha256,
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
    SELECT p.tenant_scope_id,p.site_id,p.policy_id,p.policy_kind,p.policy_version,p.expected_active_version,
           p.bundle_sha256,p.canonical_payload_sha256,p.runtime_snapshot_sha256,p.signing_key_id,
           t.node_id INTO publication
    FROM security_policy_publications p
    JOIN security_policy_publication_targets t ON t.tenant_scope_id=p.tenant_scope_id AND t.publication_id=p.id AND t.binding_id=p.binding_id
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
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_binding_valid
BEFORE INSERT ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION validate_firewall_command_outbox_binding();

DROP TRIGGER global_firewall_publication_no_truncate ON global_firewall_publication_outbox;
DROP TRIGGER global_firewall_publication_guard ON global_firewall_publication_outbox;
DROP TRIGGER global_firewall_receipts_no_truncate ON global_firewall_write_receipts;
DROP TRIGGER global_firewall_revisions_no_truncate ON global_firewall_policy_revisions;
DROP TRIGGER global_firewall_receipts_append_only ON global_firewall_write_receipts;
DROP TRIGGER global_firewall_revisions_append_only ON global_firewall_policy_revisions;
DROP FUNCTION protect_global_firewall_publication_134();
DROP FUNCTION prevent_global_firewall_fact_truncate_134();
DROP FUNCTION prevent_global_firewall_fact_mutation_134();

DROP TABLE global_firewall_publication_outbox;
DROP TABLE global_firewall_write_receipts;
DROP TABLE global_firewall_policy_revisions;
DROP TABLE global_firewall_policies;

DELETE FROM role_permissions WHERE permission_name IN ('firewall.read','firewall.manage');
DELETE FROM permissions WHERE name IN ('firewall.read','firewall.manage');
