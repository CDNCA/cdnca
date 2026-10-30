DO $$
DECLARE
    definition text;
    needle text := E'IF EXISTS (\n            SELECT 1 FROM edge_config_publications publication\n            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1\n        ) OR (NEW.action = ''rollback'' AND EXISTS (\n            SELECT 1 FROM edge_config_publications publication\n            WHERE publication.configuration_scope_id = NEW.configuration_scope_id\n              AND publication.config_version_id = NEW.config_version_id\n              AND publication.contract_version = 1\n        )) THEN';
    replacement text := E'IF EXISTS (\n            SELECT 1 FROM edge_config_publications publication\n            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1\n        ) THEN';
BEGIN
    SELECT pg_get_functiondef('assert_rollout_contract_046()'::regprocedure) INTO definition;
    IF strpos(definition, needle) = 0 THEN
        RAISE EXCEPTION 'rollback contract migration rollback cannot find publication guard' USING ERRCODE = 'P2220';
    END IF;
    EXECUTE replace(definition, needle, replacement);
END;
$$;
