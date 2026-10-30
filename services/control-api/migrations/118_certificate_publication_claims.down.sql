LOCK TABLE schema_migrations,
    certificate_publication_intent_state_facts,
    certificate_publication_intents
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 118 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 118 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=118 AND migration_id='118_certificate_publication_claims'
          AND checksum_sha256='7190a136a8c7685eb20538f86c67541a183d5631b9924d16aeb2cba511a72499'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=117 AND migration_id='117_api_key_ip_allowlist'
          AND checksum_sha256='9fa028cf6c6c65883f0289f8f12a305104e5438a10888c7970cccb08db2adccc'
          AND down_checksum_sha256='a5000b0e0561875b9533022fac293755d24a3950412aed3e2649f499c3fd4904'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 118 rollback requires the exact verified 118 head'
            USING ERRCODE='P1180';
    END IF;
    IF EXISTS (
        SELECT 1 FROM certificate_publication_intent_state_facts WHERE sequence>1
    ) THEN
        RAISE EXCEPTION 'migration 118 rollback would discard certificate publication worker facts'
            USING ERRCODE='P1182';
    END IF;
END;
$$;

DROP TRIGGER certificate_publication_intent_initialize_118 ON certificate_publication_intents;
DROP FUNCTION initialize_certificate_publication_intent_state_118();

DROP TRIGGER certificate_publication_intent_state_validate_118
    ON certificate_publication_intent_state_facts;
DROP TRIGGER certificate_publication_intent_states_no_truncate_118
    ON certificate_publication_intent_state_facts;
DROP TRIGGER certificate_publication_intent_states_immutable_118
    ON certificate_publication_intent_state_facts;
DROP FUNCTION validate_certificate_publication_intent_state_118();
DROP FUNCTION prevent_certificate_publication_intent_state_truncate_118();
DROP FUNCTION protect_certificate_publication_intent_state_118();

DROP TABLE certificate_publication_intent_state_facts;
