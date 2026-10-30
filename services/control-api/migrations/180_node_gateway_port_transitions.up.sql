LOCK TABLE schema_migrations,nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_180$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>179 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>179 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=179 AND migration_id='179_node_monitoring_evidence' AND
              checksum_sha256='11a46d749b7e28360aa0416c9028c69ff89acc696bf22a48e8e043b8d0b972b5' AND
              down_checksum_sha256='998579feed200188ab74b5685262a2c3d2f34acdd1564ab6b1c04f44a73e9da5' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.node_gateway_port_transitions') IS NOT NULL OR
         to_regclass(current_schema() || '.node_gateway_port_transition_command_outbox') IS NOT NULL OR
         to_regclass(current_schema() || '.node_gateway_port_transition_status_events') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 180 requires the exact verified 179 release head and an untouched gateway port transition schema'
            USING ERRCODE='P1800';
    END IF;
END;
$migration_180$;

CREATE TABLE node_gateway_port_transitions (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision>0),
    expected_node_revision bigint NOT NULL CHECK (expected_node_revision>0),
    old_endpoint text NOT NULL CHECK (old_endpoint=btrim(old_endpoint) AND char_length(old_endpoint) BETWEEN 3 AND 512),
    new_endpoint text NOT NULL CHECK (new_endpoint=btrim(new_endpoint) AND char_length(new_endpoint) BETWEEN 3 AND 512),
    server_name text NOT NULL CHECK (server_name=btrim(server_name) AND char_length(server_name) BETWEEN 1 AND 253),
    old_listen_address text NOT NULL CHECK (old_listen_address=btrim(old_listen_address) AND char_length(old_listen_address) BETWEEN 3 AND 512),
    new_listen_address text NOT NULL CHECK (new_listen_address=btrim(new_listen_address) AND char_length(new_listen_address) BETWEEN 3 AND 512),
    compatibility_deadline timestamptz NOT NULL,
    rollback_deadline timestamptz NOT NULL,
    certificate_sha256 text NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('preparing','switching','switched','failed','rolled_back','finalized')),
    status_revision bigint NOT NULL DEFAULT 0 CHECK (status_revision>=0),
    active_endpoint text NOT NULL CHECK (active_endpoint IN (old_endpoint,new_endpoint)),
    error_code text NOT NULL DEFAULT '' CHECK (error_code ~ '^[a-z0-9_]{0,64}$'),
    request_id text NOT NULL UNIQUE CHECK (request_id=btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128),
    idempotency_key text NOT NULL CHECK (idempotency_key=btrim(idempotency_key) AND char_length(idempotency_key) BETWEEN 1 AND 128),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256)=32),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (old_endpoint<>new_endpoint AND old_listen_address<>new_listen_address),
    CHECK (compatibility_deadline>created_at AND rollback_deadline>compatibility_deadline),
    CHECK ((state IN ('failed','rolled_back') AND error_code<>'') OR
           (state NOT IN ('failed','rolled_back') AND error_code='')),
    UNIQUE (scope_id,node_id,revision),
    UNIQUE (scope_id,idempotency_key)
);

CREATE UNIQUE INDEX node_gateway_port_transitions_active_node_180_idx
    ON node_gateway_port_transitions(node_id)
    WHERE state NOT IN ('failed','rolled_back','finalized');
CREATE INDEX node_gateway_port_transitions_scope_created_180_idx
    ON node_gateway_port_transitions(scope_id,created_at DESC,id DESC);

CREATE TABLE node_gateway_port_transition_command_outbox (
    id uuid PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    transition_id uuid NOT NULL REFERENCES node_gateway_port_transitions(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision>0),
    action text NOT NULL CHECK (action IN ('switch','finalize','rollback')),
    subject text NOT NULL CHECK (subject=btrim(subject) AND subject ~ '^cdnca[.]agent[.]commands[.]gateway-port[.][0-9a-f-]{36}$'),
    message_id text NOT NULL UNIQUE CHECK (message_id=btrim(message_id) AND char_length(message_id) BETWEEN 1 AND 128),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
    request_id text NOT NULL CHECK (request_id=btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128),
    idempotency_key text NOT NULL CHECK (idempotency_key=btrim(idempotency_key) AND char_length(idempotency_key) BETWEEN 1 AND 128),
    state text NOT NULL CHECK (state IN ('pending','publishing','published')),
    claim_token uuid,
    claimed_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
    last_error_code text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[a-z0-9_]{0,64}$'),
    puback_stream text,
    puback_sequence bigint,
    published_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state='publishing')=(claim_token IS NOT NULL AND claimed_until IS NOT NULL)),
    CHECK ((state='published')=(puback_stream IS NOT NULL AND puback_sequence IS NOT NULL AND puback_sequence>0 AND published_at IS NOT NULL)),
    CHECK (state='published' OR puback_stream IS NULL AND puback_sequence IS NULL AND published_at IS NULL),
    UNIQUE (transition_id,action)
);

CREATE INDEX node_gateway_port_transition_outbox_claim_180_idx
    ON node_gateway_port_transition_command_outbox(state,next_attempt_at,created_at,id)
    WHERE state<>'published';

CREATE TABLE node_gateway_port_transition_status_events (
    id uuid PRIMARY KEY,
    transition_id uuid NOT NULL REFERENCES node_gateway_port_transitions(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision>0),
    status_revision bigint NOT NULL CHECK (status_revision>0),
    state text NOT NULL CHECK (state IN ('switching','switched','failed','rolled_back','finalized')),
    active_endpoint text NOT NULL CHECK (active_endpoint=btrim(active_endpoint) AND char_length(active_endpoint) BETWEEN 3 AND 512),
    certificate_sha256 text NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    error_code text NOT NULL DEFAULT '' CHECK (error_code ~ '^[a-z0-9_]{0,64}$'),
    event_id uuid NOT NULL UNIQUE,
    puback_stream text NOT NULL CHECK (puback_stream=btrim(puback_stream) AND char_length(puback_stream) BETWEEN 1 AND 128),
    puback_sequence bigint NOT NULL CHECK (puback_sequence>0),
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
	CHECK ((state IN ('failed','rolled_back') AND error_code<>'') OR
	       (state NOT IN ('failed','rolled_back') AND error_code='')),
	UNIQUE (puback_stream,puback_sequence),
    UNIQUE (transition_id,status_revision)
);

REVOKE ALL ON node_gateway_port_transitions,node_gateway_port_transition_command_outbox,
    node_gateway_port_transition_status_events FROM PUBLIC;
