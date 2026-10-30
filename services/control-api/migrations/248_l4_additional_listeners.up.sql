LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;
DO $migration_248$ BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 247 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=247 AND integrity_state='verified'
        AND checksum_sha256='c34bad9d110f882e047f9974e2921beddb1a8200cdcc4f6c57495ed5b1644032'
        AND down_checksum_sha256='d7b16f90ff536c209d535cb55f384780d30edcd05cfe598fca095c08ada44210'
    ) THEN RAISE EXCEPTION 'migration 248 requires verified 247' USING ERRCODE='P2480'; END IF;
END $migration_248$;

-- Primary listeners are a database-owned projection; extra rows are the additional-listener facts.
-- Retired IDs remain reserved for their original stream, while socket reservations are released.
CREATE TABLE l4_forward_listeners (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    stream_id uuid NOT NULL REFERENCES l4_forwards(id) ON DELETE RESTRICT,
    protocol text NOT NULL CHECK (protocol IN ('tcp','udp')),
    address text NOT NULL CHECK (address='*'),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    retired_at timestamptz CHECK (retired_at IS NULL OR isfinite(retired_at)),
    reserved boolean NOT NULL DEFAULT true
);
CREATE UNIQUE INDEX l4_forward_listeners_socket_248_idx
    ON l4_forward_listeners(protocol,port) WHERE reserved;
CREATE INDEX l4_forward_listeners_stream_248_idx ON l4_forward_listeners(stream_id);

INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port,reserved)
SELECT id,id,protocol,listen_address,listen_port,deleted_at IS NULL FROM l4_forwards;

CREATE FUNCTION protect_l4_listener_248() RETURNS trigger LANGUAGE plpgsql AS $$
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
    RETURN NEW;
END;
$$;
CREATE TRIGGER l4_listener_248_guard BEFORE INSERT OR UPDATE OR DELETE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION protect_l4_listener_248();
CREATE TRIGGER l4_listener_248_no_truncate BEFORE TRUNCATE ON l4_forward_listeners
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_listener_248();

CREATE FUNCTION sync_l4_primary_listener_248() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port)
    VALUES(NEW.id,NEW.id,NEW.protocol,NEW.listen_address,NEW.listen_port)
    ON CONFLICT(id) DO UPDATE SET protocol=EXCLUDED.protocol,address=EXCLUDED.address,port=EXCLUDED.port
    WHERE l4_forward_listeners.id=l4_forward_listeners.stream_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'stream ID is already a listener ID' USING ERRCODE='P2482';
    END IF;
    UPDATE l4_forward_listeners SET reserved=NEW.deleted_at IS NULL AND retired_at IS NULL
    WHERE stream_id=NEW.id AND id<>stream_id AND reserved IS DISTINCT FROM (NEW.deleted_at IS NULL AND retired_at IS NULL);
    RETURN NULL;
END;
$$;
CREATE TRIGGER l4_forwards_248_primary_listener AFTER INSERT OR UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION sync_l4_primary_listener_248();

CREATE FUNCTION validate_l4_runtime_spec_248(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    listener jsonb;
    listener_id uuid;
    previous_id uuid;
    sockets text[];
    socket text;
BEGIN
    IF NOT validate_l4_runtime_spec_151(target_stream_id,target_scope_id,target_site_id,runtime_spec-'additional_listeners') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'additional_listeners' THEN RETURN true; END IF;
    IF target_site_id IS NULL OR jsonb_typeof(runtime_spec->'additional_listeners')<>'array' OR
       jsonb_array_length(runtime_spec->'additional_listeners') NOT BETWEEN 1 AND 63 THEN RETURN false; END IF;
    sockets := ARRAY[(runtime_spec#>>'{listener,protocol}') || ':' || (runtime_spec#>>'{listener,port}')];
    FOR listener IN SELECT value FROM jsonb_array_elements(runtime_spec->'additional_listeners') LOOP
        IF jsonb_typeof(listener)<>'object' OR
           (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(listener) keys(key)) IS DISTINCT FROM
               ARRAY['address','id','port','protocol']::text[] OR
           jsonb_typeof(listener->'id')<>'string' OR jsonb_typeof(listener->'address')<>'string' OR
           jsonb_typeof(listener->'protocol')<>'string' OR
           jsonb_typeof(listener->'port')<>'number' OR (listener->>'port') !~ '^[1-9][0-9]{0,4}$' OR
           (listener->>'port')::integer NOT BETWEEN 1 AND 65535 OR
           listener->>'protocol' NOT IN ('tcp','udp') OR listener->>'address'<>'*' THEN RETURN false; END IF;
        listener_id := (listener->>'id')::uuid;
        IF listener_id='00000000-0000-0000-0000-000000000000'::uuid OR listener_id=target_stream_id OR
           listener_id::text<>listener->>'id' OR (previous_id IS NOT NULL AND listener_id<=previous_id) THEN RETURN false; END IF;
        socket := (listener->>'protocol') || ':' || (listener->>'port');
        IF socket=ANY(sockets) OR (listener->>'protocol'='udp' AND
            ((runtime_spec->>'proxy_protocol_inbound')::boolean OR (runtime_spec->>'proxy_protocol_outbound')::boolean)) THEN RETURN false; END IF;
        sockets := array_append(sockets,socket);
        previous_id := listener_id;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_151,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_248
    CHECK(validate_l4_runtime_spec_248(stream_id,scope_id,site_id,runtime_spec));

-- Check final transaction state: temporary release permits promoting an extra socket to primary.
-- It also rejects old writers that omit existing extras when appending a new runtime intent.
CREATE FUNCTION check_l4_listener_facts_248() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_id uuid;
    forward_row l4_forwards%ROWTYPE;
    extra_listeners jsonb;
    intent l4_publish_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='l4_forwards' THEN target_id:=NEW.id; ELSE target_id:=NEW.stream_id; END IF;
    IF NOT EXISTS(SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id) THEN
        IF TG_TABLE_NAME<>'l4_publish_intents' THEN RETURN NULL; END IF;
        IF NOT NEW.runtime_spec ? 'additional_listeners' THEN RETURN NULL; END IF;
    END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=target_id;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'protocol',protocol,'address',address,'port',port) ORDER BY id),'[]'::jsonb)
    INTO extra_listeners FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id AND retired_at IS NULL;
    IF jsonb_array_length(extra_listeners)>63 OR
       ((forward_row.proxy_protocol_inbound OR forward_row.proxy_protocol_v1) AND EXISTS (
           SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND retired_at IS NULL AND protocol='udp'
       )) THEN RAISE EXCEPTION 'invalid final listener configuration' USING ERRCODE='P2482'; END IF;
    SELECT * INTO intent FROM l4_publish_intents WHERE stream_id=target_id ORDER BY version DESC LIMIT 1;
    IF intent.id IS NULL OR intent.resource_revision<>forward_row.revision OR
       COALESCE(intent.runtime_spec->'additional_listeners','[]'::jsonb)<>extra_listeners OR
       intent.runtime_spec->'listener' IS DISTINCT FROM jsonb_build_object(
           'protocol',forward_row.protocol,'address',forward_row.listen_address,'port',forward_row.listen_port) THEN
        RAISE EXCEPTION 'listener facts require a matching versioned intent' USING ERRCODE='P2483';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER l4_listener_248_final_facts AFTER INSERT OR UPDATE ON l4_forward_listeners
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();
CREATE CONSTRAINT TRIGGER l4_forwards_248_final_facts AFTER INSERT OR UPDATE ON l4_forwards
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();
CREATE CONSTRAINT TRIGGER l4_publish_intents_248_final_facts AFTER INSERT ON l4_publish_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();

REVOKE ALL ON l4_forward_listeners FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_listener_248(),sync_l4_primary_listener_248(),
    check_l4_listener_facts_248(),validate_l4_runtime_spec_248(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT,UPDATE ON l4_forward_listeners TO cdnca_control_app;
        GRANT EXECUTE ON FUNCTION validate_l4_runtime_spec_248(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
