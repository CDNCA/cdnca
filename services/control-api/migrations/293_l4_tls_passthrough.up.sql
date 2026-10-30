LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_293_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 292 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 292 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=292 AND
        migration_id='292_node_scope_conflict_audit_index' AND
        checksum_sha256='a76b9d72641858fb17f30b14b261083c6bfeb1350ab844ccc845835dc6eeab0b' AND
        down_checksum_sha256='3d7b46b159a65c05abe4bd9bac50f750c01c09b65a1717543d9d226b32db5a54' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.l4_forward_server_names') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 293 requires the exact verified 292 release head' USING ERRCODE='P2930';
    END IF;
END;
$migration_293_up$;

-- TLS passthrough streams are told apart by SNI (decisions/multitenant-
-- composition-compat-2026-10-16, 补充 2), so they no longer own a socket
-- outright: plain sockets stay unique per (protocol, port), and each
-- (port, server name) belongs to one live passthrough listener. Names are exact
-- host names or a leading "*." wildcard, compared as written: "*.a.com" and
-- "x.a.com" coexist (exact names win at the node). Sharing with websites is
-- checked in Go (edgeconfig.FindPortConflicts) on save and on publication.
CREATE FUNCTION valid_l4_server_names_293(names text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT cardinality(names) BETWEEN 1 AND 32
       AND (SELECT count(DISTINCT name) FROM unnest(names) name) = cardinality(names)
       AND names = ARRAY(SELECT name FROM unnest(names) name ORDER BY name COLLATE "C")
       AND NOT EXISTS (
           SELECT 1 FROM unnest(names) name
           WHERE name IS NULL OR char_length(regexp_replace(name, '^\*\.', '')) > 253
              OR name !~ '^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
       )
$$;

ALTER TABLE l4_forwards
    ADD COLUMN tls_passthrough boolean NOT NULL DEFAULT false,
    ADD COLUMN server_names text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT l4_forwards_tls_passthrough_293 CHECK (
        (NOT tls_passthrough AND cardinality(server_names) = 0) OR
        (tls_passthrough AND protocol = 'tcp' AND site_id IS NOT NULL AND valid_l4_server_names_293(server_names))
    );

ALTER TABLE l4_forward_listeners
    ADD COLUMN tls_passthrough boolean NOT NULL DEFAULT false,
    ADD COLUMN server_names text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT l4_forward_listeners_tls_passthrough_293 CHECK (
        (NOT tls_passthrough AND cardinality(server_names) = 0) OR (tls_passthrough AND protocol = 'tcp')
    );

DROP INDEX l4_forwards_protocol_port_active_idx;
CREATE UNIQUE INDEX l4_forwards_protocol_port_active_293_idx ON l4_forwards(protocol, listen_port)
    WHERE deleted_at IS NULL AND NOT tls_passthrough;
DROP INDEX l4_forward_listeners_socket_248_idx;
CREATE UNIQUE INDEX l4_forward_listeners_socket_293_idx ON l4_forward_listeners(protocol, port)
    WHERE reserved AND NOT tls_passthrough;

-- One row per (passthrough listener, name) while the listener is reserved.
CREATE TABLE l4_forward_server_names (
    listener_id uuid NOT NULL REFERENCES l4_forward_listeners(id) ON DELETE RESTRICT,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    server_name text NOT NULL,
    PRIMARY KEY (listener_id, server_name)
);
CREATE UNIQUE INDEX l4_forward_server_names_port_293_idx ON l4_forward_server_names(port, server_name);

-- Listeners carry the stream's passthrough facts, so every socket of a
-- passthrough stream is claimed by name rather than outright.
CREATE FUNCTION protect_l4_listener_293() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE forward_row l4_forwards%ROWTYPE;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'listener identities must be retained' USING ERRCODE='P2482';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.stream_id<>OLD.stream_id) THEN
        RAISE EXCEPTION 'listener identity is immutable' USING ERRCODE='P2482';
    END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=NEW.stream_id FOR UPDATE;
    IF NEW.id=NEW.stream_id THEN
        IF pg_trigger_depth()<2 OR NEW.protocol<>forward_row.protocol OR
           NEW.address<>forward_row.listen_address OR NEW.port<>forward_row.listen_port OR NEW.retired_at IS NOT NULL THEN
            RAISE EXCEPTION 'primary listener is database maintained' USING ERRCODE='P2482';
        END IF;
    ELSIF forward_row.site_id IS NULL OR (forward_row.deleted_at IS NOT NULL AND pg_trigger_depth()<2) THEN
        RAISE EXCEPTION 'additional listeners require a live v2 stream' USING ERRCODE='P2482';
    END IF;
    NEW.reserved := forward_row.deleted_at IS NULL AND NEW.retired_at IS NULL;
    NEW.tls_passthrough := forward_row.tls_passthrough;
    NEW.server_names := forward_row.server_names;
    RETURN NEW;
END;
$$;
DROP TRIGGER l4_listener_248_guard ON l4_forward_listeners;
CREATE TRIGGER l4_listener_293_guard BEFORE INSERT OR UPDATE OR DELETE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION protect_l4_listener_293();

CREATE FUNCTION sync_l4_primary_listener_293() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port)
    VALUES(NEW.id,NEW.id,NEW.protocol,NEW.listen_address,NEW.listen_port)
    ON CONFLICT(id) DO UPDATE SET protocol=EXCLUDED.protocol,address=EXCLUDED.address,port=EXCLUDED.port
    WHERE l4_forward_listeners.id=l4_forward_listeners.stream_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'stream ID is already a listener ID' USING ERRCODE='P2482';
    END IF;
    UPDATE l4_forward_listeners SET reserved=NEW.deleted_at IS NULL AND retired_at IS NULL
    WHERE stream_id=NEW.id AND id<>stream_id AND (
        reserved IS DISTINCT FROM (NEW.deleted_at IS NULL AND retired_at IS NULL) OR
        tls_passthrough IS DISTINCT FROM NEW.tls_passthrough OR server_names IS DISTINCT FROM NEW.server_names);
    RETURN NULL;
END;
$$;
DROP TRIGGER l4_forwards_248_primary_listener ON l4_forwards;
CREATE TRIGGER l4_forwards_293_primary_listener AFTER INSERT OR UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION sync_l4_primary_listener_293();

CREATE FUNCTION sync_l4_server_names_293() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM l4_forward_server_names WHERE listener_id=NEW.id;
    IF NEW.reserved AND NEW.tls_passthrough THEN
        INSERT INTO l4_forward_server_names(listener_id,port,server_name)
        SELECT NEW.id, NEW.port, name FROM unnest(NEW.server_names) name;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER l4_listener_293_server_names AFTER INSERT OR UPDATE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION sync_l4_server_names_293();

-- Runtime intents of passthrough streams carry both keys; plain ones neither.
CREATE FUNCTION validate_l4_runtime_spec_293(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE names text[];
BEGIN
    IF NOT validate_l4_runtime_spec_248(target_stream_id,target_scope_id,target_site_id,
        runtime_spec-'tls_passthrough'-'server_names') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'tls_passthrough' THEN
        RETURN NOT runtime_spec ? 'server_names';
    END IF;
    IF target_site_id IS NULL OR runtime_spec->'tls_passthrough'<>'true'::jsonb OR
       jsonb_typeof(runtime_spec->'server_names')<>'array' OR
       runtime_spec#>>'{listener,protocol}'<>'tcp' OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(COALESCE(runtime_spec->'additional_listeners','[]'::jsonb)) listener
           WHERE listener->>'protocol'<>'tcp'
       ) OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(runtime_spec->'server_names') name WHERE jsonb_typeof(name)<>'string'
       ) THEN
        RETURN false;
    END IF;
    names := ARRAY(SELECT jsonb_array_elements_text(runtime_spec->'server_names'));
    RETURN valid_l4_server_names_293(names);
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_248,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_293
    CHECK(validate_l4_runtime_spec_293(stream_id,scope_id,site_id,runtime_spec));

-- The latest intent must state the stream's passthrough facts, so a writer
-- that predates 293 cannot publish names the uniqueness index never saw.
CREATE FUNCTION check_l4_passthrough_facts_293() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_id uuid;
    forward_row l4_forwards%ROWTYPE;
    intent l4_publish_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='l4_forwards' THEN target_id:=NEW.id; ELSE target_id:=NEW.stream_id; END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=target_id;
    IF forward_row.site_id IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO intent FROM l4_publish_intents WHERE stream_id=target_id ORDER BY version DESC LIMIT 1;
    IF intent.id IS NULL THEN
        IF forward_row.tls_passthrough THEN
            RAISE EXCEPTION 'passthrough facts require a matching versioned intent' USING ERRCODE='P2931';
        END IF;
        RETURN NULL;
    END IF;
    IF COALESCE(intent.runtime_spec->'tls_passthrough'='true'::jsonb, false) IS DISTINCT FROM forward_row.tls_passthrough OR
       COALESCE(intent.runtime_spec->'server_names','[]'::jsonb) IS DISTINCT FROM to_jsonb(forward_row.server_names) THEN
        RAISE EXCEPTION 'passthrough facts require a matching versioned intent' USING ERRCODE='P2931';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER l4_forwards_293_passthrough_facts AFTER INSERT OR UPDATE ON l4_forwards
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_passthrough_facts_293();
CREATE CONSTRAINT TRIGGER l4_publish_intents_293_passthrough_facts AFTER INSERT ON l4_publish_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_passthrough_facts_293();

REVOKE ALL ON l4_forward_server_names FROM PUBLIC;
REVOKE ALL ON FUNCTION valid_l4_server_names_293(text[]), protect_l4_listener_293(), sync_l4_primary_listener_293(),
    sync_l4_server_names_293(), check_l4_passthrough_facts_293(),
    validate_l4_runtime_spec_293(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT,DELETE ON l4_forward_server_names TO cdnca_control_app;
        GRANT EXECUTE ON FUNCTION valid_l4_server_names_293(text[]),
            validate_l4_runtime_spec_293(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
