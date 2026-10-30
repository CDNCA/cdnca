LOCK TABLE schema_migrations,l4_forwards,l4_forward_listeners,l4_publish_intents,l4_write_requests IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF (SELECT max(version) FROM schema_migrations)<>248 OR
       EXISTS(SELECT 1 FROM l4_forward_listeners WHERE id<>stream_id) OR
       EXISTS(SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'additional_listeners') OR
       EXISTS(SELECT 1 FROM l4_write_requests WHERE response_body ? 'additional_listeners' OR
           response_body#>'{publish_intent,runtime_spec}' ? 'additional_listeners' OR
           response_body->'runtime_spec' ? 'additional_listeners') THEN
        RAISE EXCEPTION 'retain listener facts and history during binary rollback' USING ERRCODE='P2481';
    END IF;
END $$;
DROP TRIGGER l4_forwards_248_final_facts ON l4_forwards;
DROP TRIGGER l4_publish_intents_248_final_facts ON l4_publish_intents;
DROP TRIGGER l4_forwards_248_primary_listener ON l4_forwards;
DROP TABLE l4_forward_listeners;
DROP FUNCTION check_l4_listener_facts_248();
DROP FUNCTION sync_l4_primary_listener_248();
DROP FUNCTION protect_l4_listener_248();
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_248,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_151 CHECK(validate_l4_runtime_spec_151(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_248(uuid,uuid,uuid,jsonb);
