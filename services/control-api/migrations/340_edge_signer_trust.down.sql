LOCK TABLE schema_migrations, edge_signer_trust_documents, edge_signer_trust_events,
    edge_signer_trust_node_state IN ACCESS EXCLUSIVE MODE;

DO $migration_340_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 340 OR
       (SELECT max(version) FROM schema_migrations) <> 340 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=340 AND
        migration_id='340_edge_signer_trust' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 340 down requires the exact verified migration head' USING ERRCODE='P3401';
    END IF;
    -- An accepted revocation must not silently disappear from nodes.
    IF EXISTS (SELECT 1 FROM edge_signer_trust_documents) THEN
        RAISE EXCEPTION 'migration 340 down refuses to drop accepted edge signer trust documents' USING ERRCODE='P3403';
    END IF;
END;
$migration_340_down$;

DROP TABLE edge_signer_trust_node_state;
DROP TABLE edge_signer_trust_events;
DROP TABLE edge_signer_trust_documents;
DROP FUNCTION protect_edge_signer_trust_340();
