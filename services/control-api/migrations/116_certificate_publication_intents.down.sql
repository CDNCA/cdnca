LOCK TABLE schema_migrations,
    certificate_publication_intents,
    certificate_site_binding_facts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 116 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 116 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=116 AND migration_id='116_certificate_publication_intents'
          AND checksum_sha256='c2cc44a6432bc5816ba31e1b49749a43963b3a620b36b7625ef1df7778c153d7'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 116 rollback requires the exact verified 116 head'
            USING ERRCODE='P1160';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_publication_intents) THEN
        RAISE EXCEPTION 'migration 116 rollback would discard certificate publication intents'
            USING ERRCODE='P1162';
    END IF;
END;
$$;

DROP TRIGGER certificate_binding_requires_intent_116 ON certificate_site_binding_facts;
DROP FUNCTION require_certificate_publication_intent_116();

DROP TRIGGER certificate_publication_intents_no_truncate_116 ON certificate_publication_intents;
DROP TRIGGER certificate_publication_intents_immutable_116 ON certificate_publication_intents;
DROP TRIGGER certificate_publication_intents_validate_116 ON certificate_publication_intents;
DROP FUNCTION prevent_certificate_publication_intent_truncate_116();
DROP FUNCTION protect_certificate_publication_intent_116();
DROP FUNCTION validate_certificate_publication_intent_116();

DROP TABLE certificate_publication_intents;
ALTER TABLE certificate_site_binding_facts DROP COLUMN binding_xact_id;
