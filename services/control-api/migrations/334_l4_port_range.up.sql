LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_334_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 333 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 333 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=333 AND
        migration_id='333_security_activation_node_artifacts' AND
        checksum_sha256='5e9e7605e6cabc43ff1af6cd38cf0f22849dc07f664d18daeb199cf551b97d36' AND
        down_checksum_sha256='f5c379562defa2787322ccea73abf03dc44fbca6e181e1f8cac655c21bc08cef' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='listen_port_end'
       ) THEN
        RAISE EXCEPTION 'migration 334 requires the exact verified 333 release head' USING ERRCODE='P3340';
    END IF;
END;
$migration_334_up$;

-- Port ranges and follow-port origins of v2 streams (v6.1.0 #4,
-- docs/architecture/l4-v6-fields.md). A listener with port_end is
-- port..port_end: at most 1000 ports, never covering the node's own ports
-- 80/443/18080/18443 (edgeconfig.ValidL4PortRange), never TLS passthrough.
-- follow_port connects to the origin on the client's port; the stored
-- upstream port is then the primary listen port.
CREATE FUNCTION valid_l4_port_range_334(port integer, port_end integer) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT port_end IS NULL OR (
        port_end > port AND port_end <= 65535 AND port_end - port < 1000 AND
        NOT EXISTS (SELECT 1 FROM unnest(ARRAY[80,443,18080,18443]) protected WHERE protected BETWEEN port AND port_end)
    )
$$;

ALTER TABLE l4_forwards
    ADD COLUMN listen_port_end integer,
    ADD COLUMN upstream_follow_port boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT l4_forwards_port_range_334 CHECK (
        valid_l4_port_range_334(listen_port, listen_port_end) AND
        (listen_port_end IS NULL OR (site_id IS NOT NULL AND NOT tls_passthrough)) AND
        (NOT upstream_follow_port OR (site_id IS NOT NULL AND upstream_port = listen_port))
    );

ALTER TABLE l4_forward_listeners
    ADD COLUMN port_end integer,
    ADD CONSTRAINT l4_forward_listeners_port_range_334 CHECK (
        valid_l4_port_range_334(port, port_end) AND (port_end IS NULL OR NOT tls_passthrough)
    );

-- A reserved plain socket owns every port of its range on its protocol.
-- (Passthrough listeners share by SNI; a range overlapping one is refused in
-- Go, l4forward.rejectStreamSocketConflict.)
ALTER TABLE l4_forward_listeners
    ADD CONSTRAINT l4_forward_listeners_tcp_range_334 EXCLUDE USING gist (
        int4range(port, COALESCE(port_end, port), '[]') WITH &&
    ) WHERE (reserved AND NOT tls_passthrough AND protocol = 'tcp'),
    ADD CONSTRAINT l4_forward_listeners_udp_range_334 EXCLUDE USING gist (
        int4range(port, COALESCE(port_end, port), '[]') WITH &&
    ) WHERE (reserved AND NOT tls_passthrough AND protocol = 'udp');

-- The primary row also carries the stream's listen_port_end.
CREATE FUNCTION protect_l4_listener_334() RETURNS trigger LANGUAGE plpgsql AS $$
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
           NEW.address<>forward_row.listen_address OR NEW.port<>forward_row.listen_port OR
           NEW.port_end IS DISTINCT FROM forward_row.listen_port_end OR NEW.retired_at IS NOT NULL THEN
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
DROP TRIGGER l4_listener_293_guard ON l4_forward_listeners;
CREATE TRIGGER l4_listener_334_guard BEFORE INSERT OR UPDATE OR DELETE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION protect_l4_listener_334();

CREATE FUNCTION sync_l4_primary_listener_334() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port,port_end)
    VALUES(NEW.id,NEW.id,NEW.protocol,NEW.listen_address,NEW.listen_port,NEW.listen_port_end)
    ON CONFLICT(id) DO UPDATE SET protocol=EXCLUDED.protocol,address=EXCLUDED.address,port=EXCLUDED.port,
        port_end=EXCLUDED.port_end
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
DROP TRIGGER l4_forwards_293_primary_listener ON l4_forwards;
CREATE TRIGGER l4_forwards_334_primary_listener AFTER INSERT OR UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION sync_l4_primary_listener_334();

-- Runtime intents carry listener.port_end / additional_listeners[].port_end
-- for ranges and endpoint.follow_port=true for follow-port streams; others
-- omit them. Stripped of them, the intent is a valid 328 intent.
CREATE FUNCTION validate_l4_runtime_spec_334(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    stripped jsonb := runtime_spec;
    socket jsonb;
    sockets jsonb;
    ranged boolean := false;
BEGIN
    IF runtime_spec ? 'listener' THEN
        stripped := jsonb_set(stripped, '{listener}', (runtime_spec->'listener')-'port_end');
        ranged := COALESCE(runtime_spec->'listener' ? 'port_end', false);
    END IF;
    IF runtime_spec ? 'endpoint' THEN
        stripped := jsonb_set(stripped, '{endpoint}', (runtime_spec->'endpoint')-'follow_port');
    END IF;
    IF runtime_spec ? 'additional_listeners' AND jsonb_typeof(runtime_spec->'additional_listeners')='array' THEN
        stripped := jsonb_set(stripped, '{additional_listeners}', COALESCE((
            SELECT jsonb_agg(item-'port_end' ORDER BY ordinality)
            FROM jsonb_array_elements(runtime_spec->'additional_listeners') WITH ORDINALITY elements(item, ordinality)
        ), '[]'::jsonb));
    END IF;
    IF NOT validate_l4_runtime_spec_328(target_stream_id,target_scope_id,target_site_id,stripped) THEN
        RETURN false;
    END IF;
    sockets := jsonb_build_array(runtime_spec->'listener') || COALESCE(runtime_spec->'additional_listeners','[]'::jsonb);
    FOR socket IN SELECT value FROM jsonb_array_elements(sockets) LOOP
        IF socket ? 'port_end' THEN
            ranged := true;
            IF jsonb_typeof(socket->'port_end')<>'number' OR (socket->>'port_end') !~ '^[1-9][0-9]{0,4}$' OR
               NOT valid_l4_port_range_334((socket->>'port')::integer,(socket->>'port_end')::integer) THEN
                RETURN false;
            END IF;
        END IF;
    END LOOP;
    IF ranged THEN
        -- v2 only, never split by SNI, and no two sockets of one protocol overlap.
        IF target_site_id IS NULL OR runtime_spec ? 'tls_passthrough' OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(sockets) WITH ORDINALITY l(item, i)
            JOIN jsonb_array_elements(sockets) WITH ORDINALITY r(item, j) ON i < j
            WHERE l.item->>'protocol' = r.item->>'protocol' AND
                int4range((l.item->>'port')::integer, COALESCE((l.item->>'port_end')::integer,(l.item->>'port')::integer), '[]') &&
                int4range((r.item->>'port')::integer, COALESCE((r.item->>'port_end')::integer,(r.item->>'port')::integer), '[]')
        ) THEN
            RETURN false;
        END IF;
    END IF;
    IF COALESCE(runtime_spec->'endpoint' ? 'follow_port', false) AND (
        target_site_id IS NULL OR runtime_spec#>'{endpoint,follow_port}'<>'true'::jsonb OR
        runtime_spec#>'{endpoint,port}' IS DISTINCT FROM runtime_spec#>'{listener,port}') THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_328,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_334
    CHECK(validate_l4_runtime_spec_334(stream_id,scope_id,site_id,runtime_spec));

-- 248's final listener facts with port ranges and follow_port: the latest
-- intent must state them, so a writer that predates 334 cannot publish a
-- stream whose stored range or follow-port it does not know.
CREATE FUNCTION check_l4_listener_facts_334() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_id uuid;
    forward_row l4_forwards%ROWTYPE;
    extra_listeners jsonb;
    primary_listener jsonb;
    intent l4_publish_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='l4_forwards' THEN target_id:=NEW.id; ELSE target_id:=NEW.stream_id; END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=target_id;
    IF NOT EXISTS(SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id) AND
       forward_row.listen_port_end IS NULL AND NOT forward_row.upstream_follow_port THEN
        IF TG_TABLE_NAME<>'l4_publish_intents' THEN RETURN NULL; END IF;
        IF NOT NEW.runtime_spec ? 'additional_listeners' AND NOT COALESCE(NEW.runtime_spec->'listener' ? 'port_end', false) AND
           NOT COALESCE(NEW.runtime_spec->'endpoint' ? 'follow_port', false) THEN RETURN NULL; END IF;
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'protocol',protocol,'address',address,'port',port) ||
        CASE WHEN port_end IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('port_end',port_end) END ORDER BY id),'[]'::jsonb)
    INTO extra_listeners FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id AND retired_at IS NULL;
    IF jsonb_array_length(extra_listeners)>63 OR
       ((forward_row.proxy_protocol_inbound OR forward_row.proxy_protocol_v1) AND EXISTS (
           SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND retired_at IS NULL AND protocol='udp'
       )) THEN RAISE EXCEPTION 'invalid final listener configuration' USING ERRCODE='P2482'; END IF;
    primary_listener := jsonb_build_object('protocol',forward_row.protocol,'address',forward_row.listen_address,
        'port',forward_row.listen_port) ||
        CASE WHEN forward_row.listen_port_end IS NULL THEN '{}'::jsonb
             ELSE jsonb_build_object('port_end',forward_row.listen_port_end) END;
    SELECT * INTO intent FROM l4_publish_intents WHERE stream_id=target_id ORDER BY version DESC LIMIT 1;
    IF intent.id IS NULL OR intent.resource_revision<>forward_row.revision OR
       COALESCE(intent.runtime_spec->'additional_listeners','[]'::jsonb)<>extra_listeners OR
       intent.runtime_spec->'listener' IS DISTINCT FROM primary_listener OR
       (forward_row.site_id IS NOT NULL AND
        COALESCE(intent.runtime_spec#>'{endpoint,follow_port}'='true'::jsonb, false) IS DISTINCT FROM forward_row.upstream_follow_port) THEN
        RAISE EXCEPTION 'listener facts require a matching versioned intent' USING ERRCODE='P2483';
    END IF;
    RETURN NULL;
END;
$$;
DROP TRIGGER l4_listener_248_final_facts ON l4_forward_listeners;
DROP TRIGGER l4_forwards_248_final_facts ON l4_forwards;
DROP TRIGGER l4_publish_intents_248_final_facts ON l4_publish_intents;
CREATE CONSTRAINT TRIGGER l4_listener_334_final_facts AFTER INSERT OR UPDATE ON l4_forward_listeners
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_334();
CREATE CONSTRAINT TRIGGER l4_forwards_334_final_facts AFTER INSERT OR UPDATE ON l4_forwards
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_334();
CREATE CONSTRAINT TRIGGER l4_publish_intents_334_final_facts AFTER INSERT ON l4_publish_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_334();

REVOKE ALL ON FUNCTION valid_l4_port_range_334(integer,integer), protect_l4_listener_334(),
    sync_l4_primary_listener_334(), check_l4_listener_facts_334(),
    validate_l4_runtime_spec_334(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION valid_l4_port_range_334(integer,integer),
            validate_l4_runtime_spec_334(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
