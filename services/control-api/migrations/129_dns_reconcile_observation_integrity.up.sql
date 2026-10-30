LOCK TABLE schema_migrations, dns_reconcile_propagation_attempts
IN ACCESS EXCLUSIVE MODE;

CREATE TEMPORARY TABLE dns_reconcile_observation_expected_129 (
    classification text NOT NULL CONSTRAINT classification_076 CHECK (classification IN (
        'healthy', 'missing_record', 'wrong_value', 'cname_chain', 'cname_loop',
        'cname_depth_exceeded', 'nxdomain', 'servfail', 'timeout',
        'authority_inconsistent', 'public_propagating', 'public_propagation_failed',
        'resolver_failure', 'malformed_response'
    )),
    check_result jsonb NOT NULL CONSTRAINT check_result_076 CHECK (
        jsonb_typeof(check_result) = 'object' AND
        octet_length(check_result::text) BETWEEN 2 AND 1048576
    )
) ON COMMIT DROP;

DO $migration_129$
DECLARE
    classification_exact boolean;
    check_result_exact boolean;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 128 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 128 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=128 AND migration_id='128_notification_outbox_settlement_constraint'
          AND checksum_sha256='7a6e8595c4487e733b1033c308878f1a8a4c413a6b05c998960c87638434622d'
          AND down_checksum_sha256='32001dbf6ae3021288c9dcbae1d0f256ef8a7372d72b6e4fa7cf13223e471915'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 129 requires the exact verified 128 release head'
            USING ERRCODE='P1290';
    END IF;

    SELECT count(*)=1 AND bool_and(
        constraint_row.contype='c' AND constraint_row.convalidated AND
        pg_get_expr(constraint_row.conbin,constraint_row.conrelid,false)=(
            SELECT pg_get_expr(expected.conbin,expected.conrelid,false)
            FROM pg_constraint expected
            WHERE expected.conrelid='pg_temp.dns_reconcile_observation_expected_129'::regclass
              AND expected.conname='classification_076'
        )
    ) INTO classification_exact
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid='dns_reconcile_propagation_attempts'::regclass
      AND constraint_row.conname='dns_reconcile_propagation_attempts_classification_check';

    SELECT count(*)=1 AND bool_and(
        constraint_row.contype='c' AND constraint_row.convalidated AND
        pg_get_expr(constraint_row.conbin,constraint_row.conrelid,false)=(
            SELECT pg_get_expr(expected.conbin,expected.conrelid,false)
            FROM pg_constraint expected
            WHERE expected.conrelid='pg_temp.dns_reconcile_observation_expected_129'::regclass
              AND expected.conname='check_result_076'
        )
    ) INTO check_result_exact
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid='dns_reconcile_propagation_attempts'::regclass
      AND constraint_row.conname='dns_reconcile_propagation_attempts_check_result_check';

    IF classification_exact IS DISTINCT FROM true OR check_result_exact IS DISTINCT FROM true OR
       to_regprocedure('dns_reconcile_check_result_valid_129(jsonb,uuid,text)') IS NOT NULL OR
       EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='dns_reconcile_propagation_attempts'::regclass
          AND conname='dns_reconcile_observation_integrity_129'
    ) THEN
        RAISE EXCEPTION 'migration 129 DNS observation baseline is unexpected'
            USING ERRCODE='P1290';
    END IF;
END;
$migration_129$;

DROP TABLE pg_temp.dns_reconcile_observation_expected_129;

CREATE FUNCTION dns_reconcile_check_result_valid_129(
    candidate jsonb,
    expected_tenant_id uuid,
    expected_classification text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path=pg_catalog
AS $$
DECLARE
    observation jsonb;
    saw_authoritative boolean := false;
    saw_public boolean := false;
BEGIN
    IF candidate=jsonb_build_object('status',expected_classification) THEN
        RETURN true;
    END IF;
    IF jsonb_typeof(candidate)<>'object' OR
       candidate->>'TenantID' IS DISTINCT FROM expected_tenant_id::text OR
       candidate->>'Status' IS DISTINCT FROM expected_classification OR
       jsonb_typeof(candidate->'CheckedAt')<>'string' OR
       candidate->>'CheckedAt' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^[:cntrl:]]+(Z|[+-][0-9]{2}:[0-9]{2})$' OR
       jsonb_typeof(candidate->'RepairPlan')<>'object' OR
       jsonb_typeof(candidate->'Observations')<>'array' THEN
        RETURN false;
    END IF;

    FOR observation IN SELECT value FROM jsonb_array_elements(candidate->'Observations') LOOP
        IF jsonb_typeof(observation)<>'object' OR
           observation->>'Role' NOT IN ('authoritative','public_recursive') OR
           jsonb_typeof(observation->'Resolver')<>'string' OR
           octet_length(observation->>'Resolver') NOT BETWEEN 1 AND 255 OR
           observation->>'Resolver'<>btrim(observation->>'Resolver') OR
           observation->>'Resolver' ~ '[[:cntrl:]]' OR
           observation->>'Status' NOT IN (
               'healthy','missing_record','wrong_value','cname_chain','cname_loop',
               'cname_depth_exceeded','nxdomain','nodata','servfail','timeout',
               'authority_inconsistent','public_propagating','public_propagation_failed',
               'resolver_failure','malformed_response'
           ) THEN
            RETURN false;
        END IF;
        saw_authoritative := saw_authoritative OR observation->>'Role'='authoritative';
        saw_public := saw_public OR observation->>'Role'='public_recursive';
    END LOOP;
    RETURN saw_authoritative AND saw_public;
END;
$$;

ALTER TABLE dns_reconcile_propagation_attempts
    DROP CONSTRAINT dns_reconcile_propagation_attempts_classification_check,
    ADD CONSTRAINT dns_reconcile_propagation_attempts_classification_check CHECK (classification IN (
        'healthy', 'missing_record', 'wrong_value', 'cname_chain', 'cname_loop',
        'cname_depth_exceeded', 'nxdomain', 'nodata', 'servfail', 'timeout',
        'authority_inconsistent', 'public_propagating', 'public_propagation_failed',
        'resolver_failure', 'malformed_response'
    )),
    ADD CONSTRAINT dns_reconcile_observation_integrity_129 CHECK (
        dns_reconcile_check_result_valid_129(check_result,tenant_id,classification)
    ) NOT VALID;
