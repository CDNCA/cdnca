LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_334_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 334 OR
       (SELECT max(version) FROM schema_migrations) <> 334 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=334 AND
        migration_id='334_l4_port_range' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 334 down requires the exact verified migration head' USING ERRCODE='P3341';
    END IF;
    -- A port range, a follow-port origin or their history cannot be expressed before 334.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE listen_port_end IS NOT NULL OR upstream_follow_port) OR
       EXISTS (SELECT 1 FROM l4_forward_listeners WHERE port_end IS NOT NULL) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec::text LIKE '%"port_end"%' OR
           runtime_spec::text LIKE '%"follow_port"%') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE response_body::text LIKE '%"port_end"%' OR
           response_body::text LIKE '%"follow_port"%' OR
           COALESCE(response_body->>'listen_port_end','0') NOT IN ('0','null') OR
           COALESCE(response_body->>'upstream_follow_port','false')<>'false') THEN
        RAISE EXCEPTION 'retain L4 port ranges and history during binary rollback' USING ERRCODE='P3342';
    END IF;
END;
$migration_334_down$;

DROP TRIGGER l4_listener_334_final_facts ON l4_forward_listeners;
DROP TRIGGER l4_forwards_334_final_facts ON l4_forwards;
DROP TRIGGER l4_publish_intents_334_final_facts ON l4_publish_intents;
CREATE CONSTRAINT TRIGGER l4_listener_248_final_facts AFTER INSERT OR UPDATE ON l4_forward_listeners
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();
CREATE CONSTRAINT TRIGGER l4_forwards_248_final_facts AFTER INSERT OR UPDATE ON l4_forwards
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();
CREATE CONSTRAINT TRIGGER l4_publish_intents_248_final_facts AFTER INSERT ON l4_publish_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_l4_listener_facts_248();
DROP FUNCTION check_l4_listener_facts_334();

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_334,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_328
    CHECK(validate_l4_runtime_spec_328(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_334(uuid,uuid,uuid,jsonb);

DROP TRIGGER l4_forwards_334_primary_listener ON l4_forwards;
CREATE TRIGGER l4_forwards_293_primary_listener AFTER INSERT OR UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION sync_l4_primary_listener_293();
DROP FUNCTION sync_l4_primary_listener_334();
DROP TRIGGER l4_listener_334_guard ON l4_forward_listeners;
CREATE TRIGGER l4_listener_293_guard BEFORE INSERT OR UPDATE OR DELETE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION protect_l4_listener_293();
DROP FUNCTION protect_l4_listener_334();

ALTER TABLE l4_forward_listeners DROP CONSTRAINT l4_forward_listeners_tcp_range_334,
    DROP CONSTRAINT l4_forward_listeners_udp_range_334,
    DROP CONSTRAINT l4_forward_listeners_port_range_334, DROP COLUMN port_end;
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_port_range_334,
    DROP COLUMN upstream_follow_port, DROP COLUMN listen_port_end;
DROP FUNCTION valid_l4_port_range_334(integer,integer);
