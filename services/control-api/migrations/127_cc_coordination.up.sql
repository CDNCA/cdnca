LOCK TABLE schema_migrations,access_scopes,memberships,sites,nodes,
    security_policies,security_policy_versions,security_policy_site_bindings,
    security_policy_publications IN ACCESS EXCLUSIVE MODE;

DO $migration_127$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 126 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 126 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=126 AND migration_id='126_cname_allocation_targets'
          AND checksum_sha256='5d239cc8130826c7eb045484c3090d17b33c148f33f689bfdaa18e3637c1c257'
          AND down_checksum_sha256='90327e96a466d28b6fc0ce15ebb1584933fa722eb4f7f43870b73a2e3cf6725a'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 127 requires the exact verified 126 release head'
            USING ERRCODE='P1270';
    END IF;
END;
$migration_127$;

CREATE TABLE cc_coordination_settings (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL,
    source_cc_policy_id uuid NOT NULL,
    source_policy_kind text NOT NULL DEFAULT 'cc' CHECK (source_policy_kind='cc'),
    source_cc_policy_version bigint NOT NULL CHECK (source_cc_policy_version > 0),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    hit_threshold integer NOT NULL CHECK (hit_threshold BETWEEN 2 AND 1000000),
    node_threshold integer NOT NULL CHECK (node_threshold BETWEEN 2 AND 10000),
    window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 1 AND 3600),
    fact_ttl_seconds integer NOT NULL CHECK (
        fact_ttl_seconds BETWEEN window_seconds AND 86400
    ),
    block_seconds integer NOT NULL CHECK (block_seconds BETWEEN 1 AND 86400),
    release_hold_seconds integer NOT NULL CHECK (
        release_hold_seconds BETWEEN block_seconds AND 604800
    ),
    max_facts_per_message integer NOT NULL CHECK (max_facts_per_message BETWEEN 1 AND 1000),
    max_active_states integer NOT NULL CHECK (max_active_states BETWEEN 1 AND 1000000),
    max_claims integer NOT NULL CHECK (max_claims BETWEEN 1 AND 1000),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 16),
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,id,revision),
    UNIQUE (tenant_scope_id,site_id,revision),
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,source_cc_policy_id,source_policy_kind)
        REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT,
    FOREIGN KEY (source_cc_policy_id,source_cc_policy_version)
        REFERENCES security_policy_versions(policy_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (actor_scope_id=tenant_scope_id)
);

CREATE TABLE cc_coordination_setting_targets (
    tenant_scope_id uuid NOT NULL,
    settings_id uuid NOT NULL,
    settings_revision bigint NOT NULL,
    node_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (settings_id,node_id),
    FOREIGN KEY (tenant_scope_id,settings_id,settings_revision)
        REFERENCES cc_coordination_settings(tenant_scope_id,id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,node_id)
        REFERENCES nodes(scope_id,id) ON DELETE RESTRICT
);

CREATE TABLE cc_coordination_facts (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    settings_id uuid NOT NULL,
    settings_revision bigint NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL,
    message_id text NOT NULL CHECK (
        char_length(message_id) BETWEEN 1 AND 128 AND
        message_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    event_id text NOT NULL CHECK (
        char_length(event_id) BETWEEN 1 AND 128 AND
        event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    config_version_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    host text NOT NULL CHECK (
        host=lower(btrim(host)) AND char_length(host) BETWEEN 1 AND 253 AND
        host !~ '[[:cntrl:]/]'
    ),
    path text NOT NULL CHECK (
        left(path,1)='/' AND char_length(path) BETWEEN 1 AND 2048 AND
        path !~ '[[:cntrl:]]'
    ),
    method text NOT NULL CHECK (
        char_length(method) BETWEEN 1 AND 16 AND method ~ '^[A-Z]+$'
    ),
    listen_port integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    protocol text NOT NULL CHECK (protocol IN ('http','https')),
    request_class text NOT NULL CHECK (request_class IN (
        'standard','websocket','sse','task_stream','import','acme','health'
    )),
    client_cidr cidr NOT NULL CHECK (masklen(client_cidr) > 0),
    action text NOT NULL CHECK (
        char_length(action) BETWEEN 1 AND 64 AND action ~ '^[a-z][a-z0-9_]*$'
    ),
    status_code integer NOT NULL CHECK (status_code BETWEEN 400 AND 599),
    occurred_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,id),
    UNIQUE (tenant_scope_id,event_id),
    FOREIGN KEY (tenant_scope_id,settings_id,settings_revision)
        REFERENCES cc_coordination_settings(tenant_scope_id,id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,node_id)
        REFERENCES nodes(scope_id,id) ON DELETE RESTRICT,
    CHECK (expires_at > occurred_at AND received_at >= occurred_at)
);

CREATE INDEX cc_coordination_facts_window_idx
    ON cc_coordination_facts (tenant_scope_id,site_id,occurred_at,id);
CREATE INDEX cc_coordination_facts_expiry_idx
    ON cc_coordination_facts (expires_at,id);

CREATE TABLE cc_coordination_states (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    settings_id uuid NOT NULL,
    settings_revision bigint NOT NULL,
    site_id uuid NOT NULL,
    source_cc_policy_id uuid NOT NULL,
    aggregate_digest bytea NOT NULL CHECK (octet_length(aggregate_digest)=32),
    rule_id uuid NOT NULL,
    host text NOT NULL,
    path text NOT NULL,
    method text NOT NULL,
    listen_port integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    protocol text NOT NULL CHECK (protocol IN ('http','https')),
    request_class text NOT NULL CHECK (request_class='standard'),
    client_cidr cidr NOT NULL CHECK (masklen(client_cidr) > 0),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN (
        'monitoring','block_pending','blocked','release_pending','released','failed'
    )),
    reason_code text NOT NULL CHECK (reason_code IN (
        'cc_cross_node_threshold_reached','cc_coordination_dependency_unavailable',
        'false_positive_confirmed','cc_coordination_capacity_rejected',
        'cc_coordination_scope_rejected'
    )),
    hit_count bigint NOT NULL CHECK (hit_count >= 0),
    node_count integer NOT NULL CHECK (node_count >= 0),
    current_policy_version bigint CHECK (current_policy_version > 0),
    lkg_policy_version bigint CHECK (lkg_policy_version > 0),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest)=32),
    last_fact_id uuid NOT NULL,
    window_started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    release_hold_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,id),
    UNIQUE (tenant_scope_id,site_id,aggregate_digest),
    FOREIGN KEY (tenant_scope_id,settings_id,settings_revision)
        REFERENCES cc_coordination_settings(tenant_scope_id,id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,last_fact_id)
        REFERENCES cc_coordination_facts(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (source_cc_policy_id,current_policy_version)
        REFERENCES security_policy_versions(policy_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (source_cc_policy_id,lkg_policy_version)
        REFERENCES security_policy_versions(policy_id,revision) ON DELETE RESTRICT,
    CHECK (expires_at > window_started_at AND release_hold_until >= expires_at),
    CHECK (current_policy_version IS NULL OR lkg_policy_version IS NOT NULL)
);

CREATE INDEX cc_coordination_states_expiry_idx
    ON cc_coordination_states (expires_at,tenant_scope_id,id);

CREATE TABLE cc_coordination_actions (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    state_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    operation text NOT NULL CHECK (operation IN ('block','release')),
    reason_code text NOT NULL CHECK (reason_code IN (
        'cc_cross_node_threshold_reached','false_positive_confirmed'
    )),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    expected_active_policy_version bigint NOT NULL CHECK (expected_active_policy_version >= 0),
    decision_payload bytea NOT NULL CHECK (octet_length(decision_payload) BETWEEN 1 AND 1048576),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest)=32),
    status text NOT NULL CHECK (status IN (
        'pending','claimed','retryable','succeeded','exhausted','cancelled'
    )),
    attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 16),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 16),
    available_at timestamptz NOT NULL,
    lease_token uuid,
    lease_owner text CHECK (
        lease_owner IS NULL OR
        (char_length(lease_owner) BETWEEN 1 AND 128 AND lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$')
    ),
    lease_expires_at timestamptz,
    publication_id uuid,
    published_policy_version bigint CHECK (published_policy_version > 0),
    result_reason_code text CHECK (
        result_reason_code IS NULL OR result_reason_code IN (
            'published','publish_retryable','publish_exhausted','generation_superseded',
            'expected_active_mismatch','cancelled'
        )
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_scope_id,id),
    UNIQUE (tenant_scope_id,idempotency_key),
    UNIQUE (tenant_scope_id,site_id,state_id,generation,sequence),
    FOREIGN KEY (tenant_scope_id,state_id)
        REFERENCES cc_coordination_states(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,publication_id)
        REFERENCES security_policy_publications(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK (attempts <= max_attempts),
    CHECK (
        (status='claimed' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL AND
         lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('pending','retryable') AND lease_token IS NULL AND lease_owner IS NULL AND
         lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status IN ('succeeded','exhausted','cancelled') AND lease_token IS NULL AND
         lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CHECK (
        (status='succeeded' AND publication_id IS NOT NULL AND published_policy_version IS NOT NULL AND
         result_reason_code='published') OR
        (status<>'succeeded' AND publication_id IS NULL AND published_policy_version IS NULL)
    )
);

CREATE INDEX cc_coordination_actions_claim_idx
    ON cc_coordination_actions (status,available_at,tenant_scope_id,sequence)
    WHERE status IN ('pending','retryable');
CREATE INDEX cc_coordination_actions_lease_idx
    ON cc_coordination_actions (lease_expires_at,id)
    WHERE status='claimed';

CREATE TABLE cc_coordination_releases (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    state_id uuid NOT NULL,
    expected_generation bigint NOT NULL CHECK (expected_generation > 0),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_id text NOT NULL CHECK (
        request_id=btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code='false_positive_confirmed'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    status text NOT NULL CHECK (status IN ('pending','applied','replayed','rejected')),
    result_reason_code text CHECK (
        result_reason_code IS NULL OR result_reason_code IN (
            'released','idempotent_replay','generation_conflict','scope_rejected'
        )
    ),
    action_id uuid,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_scope_id,id),
    UNIQUE (tenant_scope_id,idempotency_key),
    FOREIGN KEY (tenant_scope_id,state_id)
        REFERENCES cc_coordination_states(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,action_id)
        REFERENCES cc_coordination_actions(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK (actor_scope_id=tenant_scope_id),
    CHECK (
        (status='pending' AND result_reason_code IS NULL AND action_id IS NULL AND completed_at IS NULL) OR
        (status='applied' AND result_reason_code='released' AND action_id IS NOT NULL AND completed_at IS NOT NULL) OR
        (status='replayed' AND result_reason_code='idempotent_replay' AND action_id IS NOT NULL AND completed_at IS NOT NULL) OR
        (status='rejected' AND result_reason_code IN ('generation_conflict','scope_rejected') AND
         action_id IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE FUNCTION protect_cc_coordination_immutable_127()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    RAISE EXCEPTION 'CC coordination provenance is append-only' USING ERRCODE='P1271';
END;
$function$;

CREATE FUNCTION protect_cc_coordination_state_127()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') OR
       ROW(NEW.id,NEW.tenant_scope_id,NEW.settings_id,NEW.settings_revision,NEW.site_id,
           NEW.source_cc_policy_id,NEW.aggregate_digest,NEW.rule_id,NEW.host,NEW.path,
           NEW.method,NEW.listen_port,NEW.protocol,NEW.request_class,NEW.client_cidr,
           NEW.window_started_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.settings_id,OLD.settings_revision,OLD.site_id,
           OLD.source_cc_policy_id,OLD.aggregate_digest,OLD.rule_id,OLD.host,OLD.path,
           OLD.method,OLD.listen_port,OLD.protocol,OLD.request_class,OLD.client_cidr,
           OLD.window_started_at) OR
       NEW.generation < OLD.generation OR NEW.updated_at < OLD.updated_at OR
       COALESCE(NEW.current_policy_version,0) < COALESCE(OLD.current_policy_version,0) OR
       COALESCE(NEW.lkg_policy_version,0) < COALESCE(OLD.lkg_policy_version,0)
    THEN
        RAISE EXCEPTION 'CC coordination state identity or generation is immutable'
            USING ERRCODE='P1272';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION protect_cc_coordination_action_127()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') OR
       ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.state_id,NEW.generation,NEW.sequence,
           NEW.operation,NEW.reason_code,NEW.idempotency_key,NEW.expected_active_policy_version,
           NEW.decision_payload,NEW.decision_digest,NEW.max_attempts,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.state_id,OLD.generation,OLD.sequence,
           OLD.operation,OLD.reason_code,OLD.idempotency_key,OLD.expected_active_policy_version,
           OLD.decision_payload,OLD.decision_digest,OLD.max_attempts,OLD.created_at) OR
       NEW.attempts < OLD.attempts OR
       OLD.status IN ('succeeded','exhausted','cancelled')
    THEN
        RAISE EXCEPTION 'CC coordination action identity or terminal settlement is immutable'
            USING ERRCODE='P1273';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION protect_cc_coordination_release_127()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') OR
       ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.state_id,NEW.expected_generation,
           NEW.idempotency_key,NEW.request_id,NEW.actor_scope_id,NEW.actor_user_id,
           NEW.reason_code,NEW.request_digest,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.state_id,OLD.expected_generation,
           OLD.idempotency_key,OLD.request_id,OLD.actor_scope_id,OLD.actor_user_id,
           OLD.reason_code,OLD.request_digest,OLD.created_at) OR OLD.status<>'pending'
    THEN
        RAISE EXCEPTION 'CC coordination release provenance is immutable'
            USING ERRCODE='P1274';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER cc_coordination_settings_immutable_127
BEFORE UPDATE OR DELETE ON cc_coordination_settings
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_settings_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_settings
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_targets_immutable_127
BEFORE UPDATE OR DELETE ON cc_coordination_setting_targets
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_targets_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_setting_targets
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_facts_immutable_127
BEFORE UPDATE OR DELETE ON cc_coordination_facts
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_facts_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_states_protected_127
BEFORE UPDATE OR DELETE ON cc_coordination_states
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_state_127();
CREATE TRIGGER cc_coordination_states_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_states
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_state_127();
CREATE TRIGGER cc_coordination_actions_protected_127
BEFORE UPDATE OR DELETE ON cc_coordination_actions
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_action_127();
CREATE TRIGGER cc_coordination_actions_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_actions
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_action_127();
CREATE TRIGGER cc_coordination_releases_protected_127
BEFORE UPDATE OR DELETE ON cc_coordination_releases
FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_release_127();
CREATE TRIGGER cc_coordination_releases_no_truncate_127
BEFORE TRUNCATE ON cc_coordination_releases
FOR EACH STATEMENT EXECUTE FUNCTION protect_cc_coordination_release_127();
