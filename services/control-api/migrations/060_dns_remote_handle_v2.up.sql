LOCK TABLE acme_issuance_challenge_events IN ACCESS EXCLUSIVE MODE;

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
            AND octet_length(remote_record_ref) BETWEEN 1 AND 2048
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

CREATE FUNCTION validate_acme_remote_record_ref_060()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.remote_record_ref IS NOT NULL AND (
        NEW.remote_record_ref <> btrim(NEW.remote_record_ref)
        OR octet_length(NEW.remote_record_ref) NOT BETWEEN 1 AND 2048
        OR NEW.remote_record_ref ~ '[[:cntrl:]]'
    ) THEN
        RAISE EXCEPTION 'invalid ACME DNS remote record reference'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER acme_issuance_challenge_remote_ref_060
BEFORE INSERT ON acme_issuance_challenge_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_remote_record_ref_060();
