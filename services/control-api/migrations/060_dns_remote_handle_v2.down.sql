LOCK TABLE acme_issuance_challenge_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM acme_issuance_challenge_events
        WHERE remote_record_ref LIKE 'v2.%'
           OR octet_length(remote_record_ref) > 1024
    ) THEN
        RAISE EXCEPTION 'cannot roll back migration 060 while v2 remote TXT handle facts exist or remote record references exceed 1024 bytes'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TRIGGER acme_issuance_challenge_remote_ref_060 ON acme_issuance_challenge_events;
DROP FUNCTION validate_acme_remote_record_ref_060();

ALTER TABLE acme_issuance_challenge_events
    DROP CONSTRAINT acme_issuance_challenge_publication_shape_048;

ALTER TABLE acme_issuance_challenge_events
    ADD CONSTRAINT acme_issuance_challenge_publication_shape_048 CHECK (
        (provider_ref IS NULL OR (
            provider_ref = btrim(provider_ref)
            AND octet_length(provider_ref) BETWEEN 1 AND 200
            AND provider_ref !~ '[[:cntrl:]]'
        ))
        AND (remote_record_ref IS NULL OR (
            remote_record_ref = btrim(remote_record_ref)
            AND octet_length(remote_record_ref) BETWEEN 1 AND 1024
            AND remote_record_ref !~ '[[:cntrl:]]'
        ))
        AND (exact_value_sha256 IS NULL OR octet_length(exact_value_sha256) = 32)
        AND (
            (provider_ref IS NULL AND remote_record_ref IS NULL)
            OR
            (provider_ref IS NOT NULL AND remote_record_ref IS NOT NULL
                AND exact_value_sha256 IS NOT NULL)
        )
    );
